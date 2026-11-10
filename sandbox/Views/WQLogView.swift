//
//  WQLogView.swift
//  sandbox
//
//  Shows wq.log. Reading happens off the main thread: the first version read
//  the whole file synchronously while a scan was still appending to it, and
//  the screen froze.
//

import SwiftUI
import UIKit

final class LogModel: ObservableObject {
    @Published var text: String?
    @Published var isLoading = false

    func load() {
        guard !isLoading else { return }
        isLoading = true
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let contents = WQLog.logContents()
            DispatchQueue.main.async {
                guard let self else { return }
                self.text = contents
                self.isLoading = false
            }
        }
    }
}

struct WQLogView: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var model = LogModel()

    var body: some View {
        NavigationStack {
            Group {
                if model.isLoading {
                    ProgressView(NSLocalizedString("loading", comment: ""))
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if let text = model.text, !text.isEmpty {
                    ScrollView {
                        Text(text)
                            .font(.caption2.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(12)
                    }
                } else {
                    VStack(spacing: 8) {
                        Image(systemName: "doc.text")
                            .font(.largeTitle)
                            .foregroundColor(.secondary)
                        Text(NSLocalizedString("log_empty", comment: ""))
                            .font(.headline)
                        Text(NSLocalizedString("log_empty_hint", comment: ""))
                            .font(.footnote)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .padding(24)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .background(Color(UIColor.systemGroupedBackground))
            .navigationTitle(NSLocalizedString("view_log", comment: ""))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(NSLocalizedString("done", comment: "")) { dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button {
                            model.load()
                        } label: {
                            Label(NSLocalizedString("retry", comment: ""), systemImage: "arrow.clockwise")
                        }
                        Button {
                            UIPasteboard.general.string = model.text ?? ""
                        } label: {
                            Label(NSLocalizedString("copy", comment: ""), systemImage: "doc.on.doc")
                        }
                        Button {
                            shareLog()
                        } label: {
                            Label(NSLocalizedString("share_log", comment: ""), systemImage: "square.and.arrow.up")
                        }
                        Divider()
                        Button(role: .destructive) {
                            WQLog.clearLog()
                            model.load()
                        } label: {
                            Label(NSLocalizedString("clear_log", comment: ""), systemImage: "trash")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
            .onAppear { model.load() }
        }
    }

    /// Shares the log file itself, so it can leave the device even when the
    /// text view is too large to render.
    private func shareLog() {
        guard let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let root = scene.keyWindow?.rootViewController else { return }
        let url = URL(fileURLWithPath: WQLog.logPath())
        let controller = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        root.present(controller, animated: true)
    }
}
