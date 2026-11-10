//
//  sandboxApp.swift
//  sandbox
//
//  Created by Đỗ Trung Thành on 13/1/26.
//

import SwiftUI

@main
struct sandboxApp: App {
    init() {
        WQLog.installCrashHandlers()
        WQLog.message("launch: \(UIDevice.current.systemName) \(UIDevice.current.systemVersion)"
                      + ", supported=\(WQAccess.isSupported() ? "yes" : "no")"
                      + ", group=\(WQAccess.appGroup() ?? "none")")
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
