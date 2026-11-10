//
//  SubscriptionScanner.swift
//  sandbox
//
//  Finds subscription records inside the containers worse_query reaches.
//  Everything below is evidence-based: it walks the containers the container
//  manager reports and only keeps files that actually parse as a StoreKit
//  receipt or a StoreKit 2 transaction.
//

import Foundation

// MARK: - Record

struct SandboxSubscription: Identifiable, Hashable {
    enum Source: String {
        case receipt = "Receipt"
        case transaction = "JWS transaction"
        case store = "Store file"
    }

    let id = UUID()
    var productID: String
    var transactionID: String?
    var originalTransactionID: String?
    var purchaseDate: Date?
    var expiresDate: Date?
    var revokedDate: Date?
    var source: Source
    /// Container (or app) the record was found in.
    var owner: String
    var sourcePath: String
    var isTrial: Bool = false

    var isExpired: Bool {
        guard let expires = expiresDate else { return false }
        return expires < Date()
    }

    var statusText: String {
        if revokedDate != nil { return "Revoked" }
        if let expires = expiresDate { return isExpired ? "Expired" : "Active" }
        return "Non-renewing"
    }

    /// Drives the row badge.
    var statusColor: String {
        if revokedDate != nil { return "red" }
        if expiresDate == nil { return "gray" }
        return isExpired ? "orange" : "green"
    }

    static func == (lhs: SandboxSubscription, rhs: SandboxSubscription) -> Bool {
        lhs.transactionID == rhs.transactionID &&
        lhs.productID == rhs.productID &&
        lhs.sourcePath == rhs.sourcePath
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(transactionID)
        hasher.combine(productID)
        hasher.combine(sourcePath)
    }
}

// MARK: - Scanner

final class SubscriptionScanner {
    struct ScanProgress {
        var scanned: Int = 0
        var total: Int = 0
        var current: String = ""
        var records: [SandboxSubscription] = []
    }

    /// Directories inside an app container that can hold StoreKit artifacts.
    private static let appSubpaths = [
        "Library/Caches",
        "Library/Application Support",
        "Library/Preferences",
        "Documents",
    ]

    /// Containers whose identifier suggests App Store / StoreKit data.
    private static let storeKeywords = ["storekit", "appstore", "itunesstore", "commerce", "store"]

    private static let interestingExtensions: Set<String> = [
        "jws", "storekit", "receipt", "transaction",
    ]

    var onProgress: ((ScanProgress) -> Void)?
    private var cancelled = false

    func cancel() { cancelled = true }

    // MARK: Scan

    func scan() -> [SandboxSubscription] {
        var records: [SandboxSubscription] = []
        var seen = Set<String>()

        func add(_ record: SandboxSubscription) {
            let key = "\(record.transactionID ?? "")|\(record.productID)|\(record.sourcePath)"
            guard !seen.contains(key) else { return }
            seen.insert(key)
            records.append(record)
        }

        func harvest(_ path: String, owner: String, source: SandboxSubscription.Source) {
            guard let data = WQAccess.data(atPath: path, maxBytes: 4 << 20) else { return }
            if let transaction = JWSParser.parse(data), let productID = transaction.productID {
                add(SandboxSubscription(
                    productID: productID,
                    transactionID: transaction.transactionID,
                    originalTransactionID: transaction.originalTransactionID,
                    purchaseDate: transaction.purchaseDate,
                    expiresDate: transaction.expiresDate,
                    revokedDate: transaction.revocationDate,
                    source: .transaction,
                    owner: owner,
                    sourcePath: path
                ))
                return
            }
            if let payload = ReceiptParser.parse(data) {
                for purchase in payload.inApp {
                    guard let productID = purchase.productID else { continue }
                    add(SandboxSubscription(
                        productID: productID,
                        transactionID: purchase.transactionID,
                        originalTransactionID: purchase.originalTransactionID,
                        purchaseDate: purchase.purchaseDate,
                        expiresDate: purchase.expiresDate,
                        revokedDate: purchase.cancellationDate,
                        source: source,
                        owner: owner,
                        sourcePath: path,
                        isTrial: purchase.isTrialPeriod || purchase.isInIntroOfferPeriod
                    ))
                }
            }
        }

        let containers = WQAccess.containers()
        report(total: max(containers.count, 1), current: "Containers", records: records)

        // App containers: bounded look into the places StoreKit writes to.
        let appContainers = containers.filter { $0.path.contains("/Data/Application/") }

        // Store containers: deeper walk, they hold the transaction records.
        let storeContainers = containers.filter { container in
            let identifier = (container.identifier ?? container.name).lowercased()
            return Self.storeKeywords.contains { identifier.contains($0) }
        }

        // App bundles, when the container manager exposes them at all.
        let bundleContainers = containers.filter {
            $0.path.contains("/Bundle/") && $0.path.hasSuffix(".app")
        }

        var index = 0
        for container in appContainers {
            if cancelled { break }
            index += 1
            let owner = Self.ownerName(for: container)
            report(total: containers.count, scanned: index, current: owner, records: records)
            for subpath in Self.appSubpaths {
                let directory = container.path + "/" + subpath
                guard WQAccess.ensureAccess(directory) else { continue }
                for item in WQAccess.childrenOfDirectory(directory) where !item.isDirectory {
                    guard item.size > 0, item.size <= (4 << 20) else { continue }
                    let name = item.name.lowercased()
                    guard name.contains("receipt") || name.contains("storekit") ||
                          Self.interestingExtensions.contains((item.path as NSString).pathExtension.lowercased()) else { continue }
                    harvest(item.path, owner: owner, source: .receipt)
                }
            }
        }

        for container in storeContainers {
            if cancelled { break }
            index += 1
            let owner = Self.ownerName(for: container)
            report(total: containers.count, scanned: index, current: owner, records: records)
            guard WQAccess.ensureAccess(container.path) else { continue }
            let hits = WQAccess.searchPath(container.path, query: "", maxDepth: 6, limit: 600, progress: nil)
            for hit in hits where !hit.isDirectory {
                guard hit.size > 0, hit.size <= (4 << 20) else { continue }
                let name = hit.name.lowercased()
                guard name.contains("receipt") || name.contains("transaction") ||
                      name.contains("storekit") || name.hasSuffix(".jws") else { continue }
                harvest(hit.path, owner: owner, source: .transaction)
            }
        }

        for container in bundleContainers {
            if cancelled { break }
            index += 1
            report(total: containers.count, scanned: index, current: container.name, records: records)
            for candidate in ["_MASReceipt/receipt", "StoreKit/receipt"] {
                let path = container.path + "/" + candidate
                guard WQAccess.exists(path) else { continue }
                harvest(path, owner: container.path.lastPathComponent, source: .receipt)
            }
        }

        return records.sorted {
            ($0.purchaseDate ?? .distantPast) > ($1.purchaseDate ?? .distantPast)
        }
    }

    private func report(total: Int, scanned: Int = 0, current: String = "", records: [SandboxSubscription] = []) {
        onProgress?(ScanProgress(scanned: scanned, total: max(total, 1), current: current, records: records))
    }

    /// A readable name for a container: bundle id when known, else its UUID.
    static func ownerName(for item: WQItem) -> String {
        if let bundleID = item.bundleID, !bundleID.isEmpty { return bundleID }
        if let identifier = item.identifier, !identifier.isEmpty { return identifier }
        return item.name
    }
}
