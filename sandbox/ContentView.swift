//
//  ContentView.swift
//  sandbox
//
//  Created by Đỗ Trung Thành on 13/1/26.
//

import SwiftUI
import StoreKit

struct ContentView: View {
    private var appVersion: String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "—"
        return "v\(version) (\(build))"
    }

    private var appIcon: UIImage? {
        guard let iconsDictionary = Bundle.main.infoDictionary?["CFBundleIcons"] as? [String: Any],
              let primaryIconsDictionary = iconsDictionary["CFBundlePrimaryIcon"] as? [String: Any],
              let iconFiles = primaryIconsDictionary["CFBundleIconFiles"] as? [String],
              let lastIcon = iconFiles.last else { return nil }
        return UIImage(named: lastIcon)
    }

    private var platformSupported: Bool { WQAccess.isSupported() }

    var body: some View {
        NavigationStack {
            List {
                // App Header Section
                Section {
                    HStack(spacing: 14) {
                        if let icon = appIcon {
                            Image(uiImage: icon)
                                .resizable()
                                .aspectRatio(contentMode: .fit)
                                .frame(width: 60, height: 60)
                                .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                        } else {
                            Image(systemName: "shippingbox.fill")
                                .font(.system(size: 28))
                                .foregroundColor(.white)
                                .frame(width: 60, height: 60)
                                .background(
                                    LinearGradient(
                                        colors: [Color.orange, Color.red],
                                        startPoint: .topLeading,
                                        endPoint: .bottomTrailing
                                    )
                                )
                                .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                        }

                        VStack(alignment: .leading, spacing: 2) {
                            Text("Sandbox")
                                .font(.title3)
                                .fontWeight(.semibold)

                            Text(NSLocalizedString("app_description", comment: ""))
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                                .lineLimit(2)
                        }
                    }
                    .padding(.vertical, 4)
                }

                // Settings Section
                Section {
                    SettingsRow(
                        icon: "gearshape.fill",
                        iconColor: .gray,
                        title: NSLocalizedString("settings_sandbox", comment: ""),
                        action: openAppSettings
                    )
                }

                // Subscriptions Section
                Section {
                    SettingsRow(
                        icon: "creditcard.fill",
                        iconColor: .blue,
                        title: NSLocalizedString("manage_sandbox_subscriptions", comment: ""),
                        action: openSandboxSubscriptions
                    )

                    SettingsRow(
                        icon: "bag.fill",
                        iconColor: .pink,
                        title: NSLocalizedString("manage_appstore_subscriptions", comment: ""),
                        showExternalLink: true,
                        action: openAppStoreSubscriptions
                    )
                } header: {
                    Text(NSLocalizedString("subscriptions_header", comment: ""))
                } footer: {
                    Text(NSLocalizedString("subscriptions_footer", comment: ""))
                }

                // Sandbox inspection, powered by worse_query
                Section {
                    NavigationLink {
                        SandboxSubscriptionsView()
                    } label: {
                        SettingsRowLabel(
                            icon: "list.bullet.rectangle.portrait.fill",
                            iconColor: .green,
                            title: NSLocalizedString("sandbox_subscriptions", comment: "")
                        )
                    }
                    .disabled(!platformSupported)

                    NavigationLink {
                        SandboxExplorerView()
                    } label: {
                        SettingsRowLabel(
                            icon: "folder.fill",
                            iconColor: .orange,
                            title: NSLocalizedString("sandbox_files", comment: "")
                        )
                    }
                    .disabled(!platformSupported)

                    NavigationLink {
                        ExploitDiagnosticsView()
                    } label: {
                        SettingsRowLabel(
                            icon: "stethoscope",
                            iconColor: .purple,
                            title: NSLocalizedString("sandbox_diagnostics", comment: "")
                        )
                    }
                } header: {
                    Text(NSLocalizedString("sandbox_section_header", comment: ""))
                } footer: {
                    Text(platformSupported
                         ? NSLocalizedString("sandbox_section_footer", comment: "")
                         : NSLocalizedString("sandbox_unsupported", comment: ""))
                }

                // Footer
                Section {
                } footer: {
                    Button(action: openCtdoWebsite) {
                        Text("\(appVersion) • © ctdoteam")
                            .font(.footnote)
                            .foregroundColor(.secondary)
                            .frame(maxWidth: .infinity)
                    }
                }
            }
            .listStyle(InsetGroupedListStyle())
            .navigationTitle("")
            .navigationBarHidden(true)
        }
    }

    private func openAppSettings() {
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(url)
    }

    private func openSandboxSubscriptions() {
        guard let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene else { return }
        Task {
            try? await AppStore.showManageSubscriptions(in: scene)
        }
    }

    private func openAppStoreSubscriptions() {
        if let url = URL(string: "https://apps.apple.com/account/subscriptions") {
            UIApplication.shared.open(url)
        }
    }

    private func openCtdoWebsite() {
        if let url = URL(string: "https://ctdo.net") {
            UIApplication.shared.open(url)
        }
    }
}

/// Row content shared by buttons and navigation links.
struct SettingsRowLabel: View {
    let icon: String
    let iconColor: Color
    let title: String
    var subtitle: String?
    var showExternalLink: Bool = false

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 14, weight: .semibold))
                .foregroundColor(.white)
                .frame(width: 28, height: 28)
                .background(iconColor)
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))

            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .foregroundColor(.primary)
                if let subtitle {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }

            Spacer()

            if showExternalLink {
                Image(systemName: "arrow.up.forward")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(Color(UIColor.tertiaryLabel))
            }
        }
    }
}

struct SettingsRow: View {
    let icon: String
    let iconColor: Color
    let title: String
    var showExternalLink: Bool = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(.white)
                    .frame(width: 28, height: 28)
                    .background(iconColor)
                    .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))

                Text(title)
                    .foregroundColor(.primary)

                Spacer()

                Image(systemName: showExternalLink ? "arrow.up.forward" : "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(Color(UIColor.tertiaryLabel))
            }
        }
    }
}

#Preview {
    ContentView()
}
