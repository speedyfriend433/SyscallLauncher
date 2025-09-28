//
//  ContentView.swift
//  SyscallLauncher
//
//  Created by 이지안 on 2025-09-28.
//

import SwiftUI
import UniformTypeIdentifiers

struct BootLogEntry: Identifiable {
    let id = UUID()
    let message: String
    let timestamp: Date
    let type: String
}

struct ContentView: View {
    @State private var bootLog: [BootLogEntry] = []
    @State private var isPickingFile = false
    @State private var bootedApps: [String] = []
    
    private var logText: String {
        bootLog.map { "\($0.timestamp.formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits))) \($0.type): \($0.message)" }.joined(separator: "\n")
    }
    
    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                Button("Select IPA") {
                    isPickingFile = true
                }
                .fileImporter(
                    isPresented: $isPickingFile,
                    allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data],
                    allowsMultipleSelection: false
                ) { result in
                    handleFilePickerResult(result)
                }
                List(bootedApps, id: \.self) { app in
                    HStack {
                        Text(app)
                        Spacer()
                        Button("PiP") {
                            addLog("Resized \(app) to PiP", type: "Multitask")
                        }
                    }
                }
                .frame(height: 100)
                
                VStack(alignment: .leading) {
                    HStack {
                        Text("Logs (\(bootLog.count))")
                            .font(.headline)
                        Spacer()
                        Button("Copy All") {
                            UIPasteboard.general.string = logText
                            addLog("Copied logs to clipboard", type: "Init")
                        }
                        .buttonStyle(.bordered)
                    }
                    List {
                        ForEach(Array(bootLog.reversed().enumerated()), id: \.element.id) { index, entry in
                            HStack {
                                Text(entry.type)
                                    .font(.caption)
                                    .foregroundStyle(logTypeColor(for: entry.type))
                                    .frame(width: 80, alignment: .leading)
                                Spacer()
                                VStack(alignment: .leading) {
                                    Text(entry.message)
                                        .font(.caption.monospaced())
                                        .textSelection(.enabled)
                                    Text(entry.timestamp.formatted(.dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits)))
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .listRowBackground(index % 2 == 0 ? Color(.systemGray6) : Color.clear)
                        }
                    }
                    .frame(height: 200)
                    .scrollDismissesKeyboard(.interactively)
                }
            }
            .navigationTitle("SyscallLauncher")
            .onAppear {
                addLog("App launched", type: "Init")
            }
            .onReceive(NotificationCenter.default.publisher(for: .SyscallLog)) { notification in
                if let message = notification.userInfo?["message"] as? String {
                    addLog(message, type: "Syscall")
                }
            }
        }
    }
    
    private func logTypeColor(for type: String) -> Color {
        switch type {
        case "Success", "Boot": return .green
        case "Error": return .red
        case "Syscall": return .blue
        case "Multitask": return .orange
        default: return .secondary
        }
    }
    
    private func handleFilePickerResult(_ result: Result<[URL], Error>) {
        switch result {
        case .success(let urls):
            if let url = urls.first {
                bootIPA(from: url)
            }
        case .failure(let error):
            addLog("File picker error: \(error.localizedDescription)", type: "Error")
        }
    }
    
    private func bootIPA(from url: URL) {
        addLog("Starting boot for \(url.lastPathComponent)", type: "Boot")
        
        guard let data = IPAPatcher.extractAndPatchIPA(from: url) else {
            addLog("Failed to patch IPA", type: "Error")
            return
        }
        
        ContainerSetup.setupIsolation(for: url.deletingPathExtension().lastPathComponent)
        
        do {
            let callback: LogCallback = swiftSyscallLogCallback
            let success = try SyscallBoot.bootApp(withPatchedData: data, logCallback: callback)
            if success {
                let appName = url.deletingPathExtension().lastPathComponent
                bootedApps.append(appName)
                addLog("Booted \(appName)", type: "Success")
            }
        } catch let error as NSError {
            addLog("Boot failed: \(error.localizedDescription)", type: "Error")
        }
    }
    
    private func addLog(_ message: String, type: String) {
        let entry = BootLogEntry(message: message, timestamp: Date(), type: type)
        bootLog.append(entry)
    }
}

#Preview {
    ContentView()
}
