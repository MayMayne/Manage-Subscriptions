//
//  WQLogView.swift
//  sandbox
//
//  Shows wq.log — the only evidence when iOS kills the app during a scan.
//

import SwiftUI

struct WQLogView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var appeared = false

    var body: some View {
        NavigationStack {
            ScrollView {
                Text(text.isEmpty ? NSLocalizedString("log_empty", comment: "") : text)
                    .font(.caption2.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
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
                            UIPasteboard.general.string = text
                        } label: {
                            Label(NSLocalizedString("copy", comment: ""), systemImage: "doc.on.doc")
                        }
                        Button(role: .destructive) {
                            WQLog.clearLog()
                            text = ""
                        } label: {
                            Label(NSLocalizedString("clear_log", comment: ""), systemImage: "trash")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
            .onAppear {
                guard !appeared else { return }
                appeared = true
                text = WQLog.logContents()
            }
        }
    }
}
