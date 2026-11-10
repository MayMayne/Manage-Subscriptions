//
//  SandboxExplorerView.swift
//  sandbox
//
//  Container browser built on worse_query.
//

import SwiftUI
import QuickLook

// MARK: - Model

final class ExplorerModel: ObservableObject {
    @Published var path: String
    @Published var items: [WQItem] = []
    @Published var isLoading = false
    @Published var errorText: String?

    init(path: String = "/var/mobile/Containers/Shared/AppGroup") {
        self.path = path
    }

    func load() {
        isLoading = true
        errorText = nil
        let target = path
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let children = WQAccess.contentsOfDirectory(target)
            let failure = WQAccess.lastError()
            DispatchQueue.main.async {
                guard let self else { return }
                self.items = children
                self.errorText = failure
                self.isLoading = false
            }
        }
    }

    func navigate(to item: WQItem) {
        path = item.path
        items = []
        load()
    }

    func goUp() {
        guard path != "/" else { return }
        path = (path as NSString).deletingLastPathComponent
        items = []
        load()
    }
}

// MARK: - Root

struct SandboxExplorerView: View {
    private struct Root: Identifiable {
        let id = UUID()
        let title: String
        let subtitle: String
        let path: String
        let icon: String
        let color: Color
    }

    private let roots: [Root] = [
        Root(title: NSLocalizedString("root_app_data", comment: ""), subtitle: "/var/mobile/Containers/Data/Application", path: "/var/mobile/Containers/Data/Application", icon: "square.stack.3d.up.fill", color: .blue),
        Root(title: NSLocalizedString("root_app_groups", comment: ""), subtitle: "/var/mobile/Containers/Shared/AppGroup", path: "/var/mobile/Containers/Shared/AppGroup", icon: "person.2.fill", color: .indigo),
        Root(title: NSLocalizedString("root_extensions", comment: ""), subtitle: "/var/mobile/Containers/Data/PluginKitPlugin", path: "/var/mobile/Containers/Data/PluginKitPlugin", icon: "puzzlepiece.extension.fill", color: .teal),
        Root(title: NSLocalizedString("root_daemons", comment: ""), subtitle: "/var/mobile/Containers/Data/InternalDaemon", path: "/var/mobile/Containers/Data/InternalDaemon", icon: "gearshape.2.fill", color: .gray),
        Root(title: NSLocalizedString("root_system_data", comment: ""), subtitle: "/var/containers/Data/System", path: "/var/containers/Data/System", icon: "internaldrive.fill", color: .orange),
        Root(title: NSLocalizedString("root_system_groups", comment: ""), subtitle: "/var/containers/Shared/SystemGroup", path: "/var/containers/Shared/SystemGroup", icon: "lock.square.stack.fill", color: .purple),
        Root(title: NSLocalizedString("root_bundles", comment: ""), subtitle: "/var/containers/Bundle/Application", path: "/var/containers/Bundle/Application", icon: "shippingbox.fill", color: .brown),
    ]

    var body: some View {
        List {
            Section {
                ForEach(roots) { root in
                    NavigationLink {
                        FileBrowserView(path: root.path)
                    } label: {
                        SettingsRowLabel(icon: root.icon, iconColor: root.color, title: root.title, subtitle: root.subtitle)
                    }
                }
            } footer: {
                Text(NSLocalizedString("explorer_footer", comment: ""))
            }

            Section {
                NavigationLink {
                    FileBrowserView(path: NSHomeDirectory())
                } label: {
                    SettingsRowLabel(icon: "house.fill", iconColor: .green,
                                     title: NSLocalizedString("root_own_sandbox", comment: ""),
                                     subtitle: NSHomeDirectory())
                }
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle(NSLocalizedString("sandbox_files", comment: ""))
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Browser

struct FileBrowserView: View {
    @StateObject private var model: ExplorerModel
    @State private var pendingURL: URL?

    init(path: String) {
        _model = StateObject(wrappedValue: ExplorerModel(path: path))
    }

    var body: some View {
        List {
            Section {
                if model.isLoading {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text(NSLocalizedString("loading", comment: ""))
                            .foregroundColor(.secondary)
                    }
                } else if let error = model.errorText {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(error)
                            .font(.footnote)
                            .foregroundColor(.red)
                        Button(NSLocalizedString("retry", comment: "")) { model.load() }
                            .font(.footnote)
                    }
                } else if model.items.isEmpty {
                    Text(NSLocalizedString("folder_empty", comment: ""))
                        .foregroundColor(.secondary)
                        .font(.footnote)
                } else {
                    ForEach(model.items, id: \.path) { item in
                        row(for: item)
                    }
                }
            } header: {
                Text(model.path)
                    .font(.caption2.monospaced())
                    .lineLimit(2)
                    .textCase(nil)
            } footer: {
                Text("\(model.items.count) \(NSLocalizedString("items", comment: ""))")
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle((model.path as NSString).lastPathComponent)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button {
                    model.goUp()
                } label: {
                    Image(systemName: "arrow.up.doc")
                }
                .disabled(model.path == "/")
            }
            ToolbarItem(placement: .navigationBarTrailing) {
                Button {
                    model.load()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
            }
        }
        .onAppear { if model.items.isEmpty { model.load() } }
        .quickLookPreview($pendingURL)
    }

    @ViewBuilder
    private func row(for item: WQItem) -> some View {
        if item.isDirectory {
            NavigationLink {
                FileBrowserView(path: item.path)
            } label: {
                label(for: item)
            }
        } else {
            Button {
                open(item)
            } label: {
                label(for: item)
            }
            .buttonStyle(.plain)
        }
    }

    private func label(for item: WQItem) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon(for: item))
                .foregroundColor(item.isDirectory ? .accentColor : .secondary)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name)
                    .lineLimit(1)
                    .font(.subheadline)
                if !item.isDirectory && item.size > 0 {
                    Text(ByteCountFormatter.string(fromByteCount: item.size, countStyle: .file))
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
            Spacer()
        }
    }

    private func icon(for item: WQItem) -> String {
        if item.isDirectory { return "folder.fill" }
        switch (item.path as NSString).pathExtension.lowercased() {
        case "plist": return "list.bullet.rectangle"
        case "db", "sqlite", "sqlite3": return "cylinder.split.1x2"
        case "jws", "json": return "doc.text.magnifyingglass"
        case "log", "txt": return "doc.text"
        case "png", "jpg", "jpeg", "heic": return "photo"
        default: return "doc"
        }
    }

    /// Copies the file into the app's own sandbox so QuickLook can show it,
    /// since the original path is outside what QL may read.
    private func open(_ item: WQItem) {
        DispatchQueue.global(qos: .userInitiated).async {
            let cache = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("preview", isDirectory: true)
            try? FileManager.default.createDirectory(at: cache, withIntermediateDirectories: true)
            let destination = cache.appendingPathComponent(item.name)
            guard let data = WQAccess.data(atPath: item.path, maxBytes: 16 << 20) else { return }
            try? data.write(to: destination)
            DispatchQueue.main.async {
                pendingURL = destination
            }
        }
    }
}
