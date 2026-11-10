//
//  SandboxSubscriptionsView.swift
//  sandbox
//
//  Lists subscriptions found in StoreKit receipts and transaction stores that
//  belong to the sandbox environment, read through worse_query.
//

import SwiftUI

final class SandboxSubscriptionsModel: ObservableObject {
    @Published var records: [SandboxSubscription] = []
    @Published var isScanning = false
    @Published var status = ""
    @Published var scanned = 0
    @Published var total = 0
    @Published var errorText: String?

    private let scanner = SubscriptionScanner()

    var progress: Double {
        guard total > 0 else { return isScanning ? 0.05 : 0 }
        return min(1, Double(scanned) / Double(total))
    }

    func scan() {
        guard !isScanning else { return }
        guard WQAccess.appGroup() != nil else {
            errorText = NSLocalizedString("sandbox_no_group", comment: "")
            return
        }
        isScanning = true
        errorText = nil
        records = []
        scanned = 0
        total = 0

        scanner.onProgress = { [weak self] progress in
            DispatchQueue.main.async {
                guard let self else { return }
                self.scanned = progress.scanned
                self.total = max(progress.total, 1)
                self.status = progress.current
            }
        }

        let scanner = self.scanner
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let found = scanner.scan()
            DispatchQueue.main.async {
                guard let self else { return }
                self.records = found
                self.isScanning = false
                self.status = found.isEmpty
                    ? NSLocalizedString("sandbox_scan_empty", comment: "")
                    : String(format: NSLocalizedString("sandbox_scan_found", comment: ""), found.count)
            }
        }
    }

    func cancel() {
        scanner.cancel()
        isScanning = false
        status = NSLocalizedString("sandbox_scan_cancelled", comment: "")
    }
}

struct SandboxSubscriptionsView: View {
    @StateObject private var model = SandboxSubscriptionsModel()
    @State private var selected: SandboxSubscription?

    var body: some View {
        List {
            Section {
                if model.isScanning {
                    VStack(alignment: .leading, spacing: 8) {
                        ProgressView(value: model.progress)
                        Text(model.status)
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                        Button(role: .destructive) {
                            model.cancel()
                        } label: {
                            Text(NSLocalizedString("cancel", comment: ""))
                                .font(.footnote)
                        }
                    }
                } else {
                    Button {
                        model.scan()
                    } label: {
                        Label(NSLocalizedString("sandbox_scan", comment: ""), systemImage: "magnifyingglass")
                    }
                }

                if let error = model.errorText {
                    Text(error)
                        .font(.footnote)
                        .foregroundColor(.red)
                } else if !model.isScanning && !model.status.isEmpty {
                    Text(model.status)
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }
            } header: {
                Text(NSLocalizedString("sandbox_scan_header", comment: ""))
            } footer: {
                Text(NSLocalizedString("sandbox_scan_footer", comment: ""))
            }

            if !model.records.isEmpty {
                Section {
                    ForEach(model.records) { record in
                        Button {
                            selected = record
                        } label: {
                            SubscriptionRow(record: record)
                        }
                        .buttonStyle(.plain)
                    }
                } header: {
                    Text(NSLocalizedString("sandbox_results_header", comment: ""))
                }
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle(NSLocalizedString("sandbox_subscriptions", comment: ""))
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: $selected) { record in
            SubscriptionDetailView(record: record)
        }
        .onAppear {
            if model.records.isEmpty && !model.isScanning { model.scan() }
        }
    }
}

private struct SubscriptionRow: View {
    let record: SandboxSubscription

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(record.productID)
                    .font(.subheadline.weight(.semibold))
                    .foregroundColor(.primary)
                    .lineLimit(1)
                Spacer()
                Text(record.statusText)
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(statusColor.opacity(0.18), in: Capsule())
                    .foregroundColor(statusColor)
            }

            if let expires = record.expiresDate {
                Text(expires, format: .dateTime.year().month().day().hour().minute())
                    .font(.caption)
                    .foregroundColor(.secondary)
            } else if let purchase = record.purchaseDate {
                Text(purchase, format: .dateTime.year().month().day().hour().minute())
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            HStack(spacing: 6) {
                Text(record.owner).lineLimit(1)
                Text("•")
                Text(record.source.rawValue)
                if record.isTrial {
                    Text("•")
                    Text("Trial")
                }
            }
            .font(.caption2)
            .foregroundColor(.secondary)
        }
        .padding(.vertical, 2)
        .contentShape(Rectangle())
    }

    private var statusColor: Color {
        switch record.statusColor {
        case "green": return .green
        case "orange": return .orange
        case "red": return .red
        default: return .gray
        }
    }
}

private struct SubscriptionDetailView: View {
    let record: SandboxSubscription
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    LabeledContent("Product", value: record.productID)
                    LabeledContent("Status", value: record.statusText)
                    if let value = record.transactionID {
                        LabeledContent("Transaction", value: value)
                    }
                    if let value = record.originalTransactionID, value != record.transactionID {
                        LabeledContent("Original", value: value)
                    }
                    LabeledContent("Container", value: record.owner)
                    LabeledContent("Source", value: record.source.rawValue)
                }

                Section {
                    if let date = record.purchaseDate {
                        LabeledContent("Purchased", value: date.formatted(date: .abbreviated, time: .shortened))
                    }
                    if let date = record.expiresDate {
                        LabeledContent("Expires", value: date.formatted(date: .abbreviated, time: .shortened))
                    }
                    if let date = record.revokedDate {
                        LabeledContent("Revoked", value: date.formatted(date: .abbreviated, time: .shortened))
                    }
                }

                Section {
                    Text(record.sourcePath)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                } header: {
                    Text("Path")
                }
            }
            .navigationTitle("Transaction")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(NSLocalizedString("done", comment: "")) { dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        UIPasteboard.general.string = record.sourcePath
                        copied = true
                    } label: {
                        Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    }
                }
            }
        }
    }
}
