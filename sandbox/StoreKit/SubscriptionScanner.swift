//
//  SubscriptionScanner.swift
//  sandbox
//
//  Finds subscription records inside the containers worse_query reaches.
//  Everything is evidence-based: it walks containers that actually open and
//  keeps only files that parse as a StoreKit receipt or transaction.
//
//  Measured reach on iOS 27.2 (device):
//    AppGroup                 189 entries     <- listable
//    /var/containers/Data/System 22 entries   <- listable
//    Data/Application, PluginKitPlugin, InternalDaemon,
//    Shared/SystemGroup, Bundle/Application   <- parent has no extension
//  The container manager query returns nothing on this release, so container
//  paths come from the container parents and from LaunchServices-style naming
//  instead of from MCM.
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

    /// `includeAppContainers` runs a file id scan, which takes minutes on a
    /// used device — only an explicit user action may set it.
    func scan(includeAppContainers: Bool = false) -> [SandboxSubscription] {
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

        let targets = Self.scanTargets(includeAppContainers: includeAppContainers)
        report(total: Swift.max(targets.count, 1), current: "Locating containers", records: records)

        for (index, target) in targets.enumerated() {
            if cancelled { break }
            report(total: targets.count, scanned: index, current: target.name, records: records)

            // Files directly inside, and one or two levels down.
            let hits = WQAccess.searchPath(target.path, query: "", maxDepth: 4, limit: 800, progress: nil)
            for hit in hits where !hit.isDirectory {
                guard hit.size > 0, hit.size <= (4 << 20) else { continue }
                let name = hit.name.lowercased()
                let ext = (hit.path as NSString).pathExtension.lowercased()
                guard name.contains("receipt") || name.contains("transaction") ||
                      name.contains("storekit") || Self.interestingExtensions.contains(ext) else { continue }
                harvest(hit.path, owner: target.name, source: .transaction)
            }

            // StoreKit writes receipts to fixed names inside app containers.
            for subpath in Self.appSubpaths {
                for leaf in ["_MASReceipt/receipt", "StoreKit/receipt", "receipt"] {
                    let candidate = target.path + "/" + subpath + "/" + leaf
                    guard WQAccess.exists(candidate) else { continue }
                    harvest(candidate, owner: target.name, source: .receipt)
                }
            }
        }

        return records.sorted {
            ($0.purchaseDate ?? .distantPast) > ($1.purchaseDate ?? .distantPast)
        }
    }

    private func report(total: Int, scanned: Int = 0, current: String = "", records: [SandboxSubscription] = []) {
        onProgress?(ScanProgress(scanned: scanned, total: Swift.max(total, 1), current: current, records: records))
    }

    // MARK: Targets

    struct Target {
        let name: String
        let path: String
    }

    /// Containers worth walking: app groups (listable), the system container
    /// root, StoreKit-looking children of the system groups, and every app
    /// container whose path can be recovered.
    static func scanTargets(includeAppContainers: Bool) -> [Target] {
        var targets: [Target] = []
        var seen = Set<String>()

        func add(_ name: String, _ path: String) {
            guard !seen.contains(path) else { return }
            seen.insert(path)
            targets.append(Target(name: name, path: path))
        }

        // 1. Container manager results (populated on some releases).
        for container in WQAccess.containers() {
            add(ownerName(for: container), container.path)
        }

        // 2. App groups: listable on 27.x, and where shared app data lives.
        for item in WQAccess.contentsOfDirectory("/var/mobile/Containers/Shared/AppGroup") {
            add(ownerName(for: item), item.path)
        }

        // 3. System container root (listable on 27.x): a "System Data" folder.
        for item in WQAccess.contentsOfDirectory("/var/containers/Data/System") {
            add(ownerName(for: item), item.path)
        }

        // 4. System groups: the parent refuses an extension but its known
        //    children open when named, so probe the ones that could hold
        //    StoreKit / commerce state.
        let systemGroupRoot = "/var/containers/Shared/SystemGroup"
        for name in knownSystemGroupNames() {
            let path = systemGroupRoot + "/" + name
            guard WQAccess.exists(path) else { continue }
            let lowercased = name.lowercased()
            guard storeKeywords.contains(where: { lowercased.contains($0) }) else { continue }
            add(name, path)
        }

        // 5. App containers: the parent is blocked but each child opens once
        //    its path is known, so use the ids the system leaked either via
        //    the app group listing or via fsgetpath.
        guard includeAppContainers else { return targets }
        for path in WQAccess.leakedChildren(ofDirectory: "/var/mobile/Containers/Data/Application",
                                            limit: 400) {
            add((path as NSString).lastPathComponent, path)
        }

        return targets
    }

    /// Names of system group containers that are worth probing. Kept small:
    /// each miss costs a query.
    static func knownSystemGroupNames() -> [String] {
        [
            "systemgroup.com.apple.storekit",
            "systemgroup.com.apple.appstore",
            "systemgroup.com.apple.itunesstore",
            "systemgroup.com.apple.commerce",
            "systemgroup.com.apple.appstored",
            "systemgroup.com.apple.mobilegestaltcache",
        ]
    }

    /// A readable name for a container: bundle id when known, else its UUID.
    static func ownerName(for item: WQItem) -> String {
        if let bundleID = item.bundleID, !bundleID.isEmpty { return bundleID }
        if let identifier = item.identifier, !identifier.isEmpty { return identifier }
        return item.name
    }
}
