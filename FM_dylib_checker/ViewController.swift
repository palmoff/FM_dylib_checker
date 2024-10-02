//  FM_dylib_checker
//
//  Created by Oleksii Dubov on 30.09.2024.
//

import Cocoa

struct FileMakerApp {
    var path: String
    var identifier: String
    var vulnerabilityStatus: String
}

class ViewController: NSViewController {

    @IBOutlet weak var tableView: NSTableView!
    @IBOutlet weak var statusLabel: NSTextField!

    var fileMakerApps: [FileMakerApp] = []
    

    var timer: Timer?
    
    let scanQueue = DispatchQueue.global(qos: .userInitiated)
    
    var isScanComplete = false
    
    override func viewDidLoad() {
        super.viewDidLoad()

        // Setup the tableView's data source and delegate
        tableView.dataSource = self
        tableView.delegate = self
    }

    // Action when Scan button is clicked
    @IBAction func scanButtonClicked(_ sender: NSButton) {
        statusLabel.stringValue = "Scanning, please wait..."
        fileMakerApps.removeAll()
        isScanComplete = false
        
        // Start background scanning
        scanQueue.async {
            self.scanForFileMakerApps {
                self.isScanComplete = true
            }
        }
        
        timer = Timer.scheduledTimer(timeInterval: 1, target: self, selector: #selector(updateTableView), userInfo: nil, repeats: true)
    }
    
    @objc func updateTableView() {
        DispatchQueue.main.async {
            self.tableView.reloadData()
            
            if self.isScanComplete {
                self.timer?.invalidate()
                self.statusLabel.stringValue = "Scan Completed"
            }
        }
    }
    
    func scanForFileMakerApps(completion: @escaping () -> Void) {
        let paths = listFileMakerAppPaths() // Get the list of FileMaker app paths
        
        paths.forEach { path in
            // Perform the vulnerability check
            if let appBundle = Bundle(path: path) {
                let identifier = appBundle.bundleIdentifier ?? ""
                
                var codeRef: SecStaticCode? = nil
                SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &codeRef)
                let vulnerability = verifyHardenedRuntimeAndProblematicEntitlements(applicationName: identifier, secStaticCode: codeRef!)

                let app = FileMakerApp(path: path, identifier: identifier, vulnerabilityStatus: vulnerability)
                DispatchQueue.main.async {
                    self.fileMakerApps.append(app) // Append to array on the main thread
                }
            }
        }
        
        completion()
    }


    func verifyHardenedRuntimeAndProblematicEntitlements(applicationName: String, secStaticCode: SecStaticCode) -> String {
        var signingInformationOptional: CFDictionary? = nil
        if SecCodeCopySigningInformation(secStaticCode, SecCSFlags(rawValue: kSecCSDynamicInformation), &signingInformationOptional) != errSecSuccess {
            return "⚠️ Vulnerable, can't get signature"
        }
        
        guard let signingInformation = signingInformationOptional else {
            return "⚠️ Vulnerable, empty"
        }
        
        let signingInformationDict = signingInformation as NSDictionary
        let signingFlagsOptional = signingInformationDict.object(forKey: "flags") as? UInt32
        
        if let signingFlags = signingFlagsOptional {
            let hardenedRuntimeFlag: UInt32 = 0x10000
            if (signingFlags & hardenedRuntimeFlag) != hardenedRuntimeFlag {
                return "⚠️ Vulnerable, dylib allowed"
            }
        } else {
            return "⚠️ Vulnerable, not signed"
        }
        
        let entitlementsOptional = signingInformationDict.object(forKey: "entitlements-dict") as? NSDictionary
        guard let entitlements = entitlementsOptional else {
            return "⚠️ Vulnerable, no entitlements"
        }
        
        let disableDylbKeyExists = entitlements["com.apple.security.cs.disable-library-validation"] != nil
        let allowDylibKeyExists = entitlements["com.apple.security.cs.allow-dyld-environment-variables"] != nil
        
        if disableDylbKeyExists && allowDylibKeyExists {
            return "⚠️ Vulnerable, dylib allowed"
        }
        
        return "✅ Not vulnerable"
    }

    func listFileMakerAppPaths() -> [String] {
        let fileManager = FileManager.default
        var fileMakerFrameworkSubdirectories: [String] = []
        
        func searchForFileMakerFramework(path: String, depth: Int) {
            if depth > 6 { return }
            
            do {
                let subdirectories = try fileManager.contentsOfDirectory(atPath: path)
                for subdirectory in subdirectories {
                    let subdirectoryPath = "\(path)/\(subdirectory)"
                    var isDirectory: ObjCBool = false
                    if fileManager.fileExists(atPath: subdirectoryPath, isDirectory: &isDirectory) {
                        if isDirectory.boolValue {
                            if subdirectory == "DBEngine.framework" {
                                fileMakerFrameworkSubdirectories.append(subdirectoryPath)
                            } else {
                                searchForFileMakerFramework(path: subdirectoryPath, depth: depth + 1)
                            }
                        }
                    }
                }
            } catch {
                print("Error: \(error)")
            }
        }
        
        var applicationsDirectoryPath: [String] = ["/Applications"]
        
        if NSUserName() != "root" {
            let userApplicationsDirectoryPath = NSString("~/Applications").expandingTildeInPath
            applicationsDirectoryPath.append(userApplicationsDirectoryPath)
        }
        
        applicationsDirectoryPath.forEach { path in
            searchForFileMakerFramework(path: path, depth: 0)
        }
        
        return fileMakerFrameworkSubdirectories
    }
}

// MARK: - NSTableView DataSource and Delegate
extension ViewController: NSTableViewDataSource, NSTableViewDelegate {

    func numberOfRows(in tableView: NSTableView) -> Int {
        return fileMakerApps.count
    }
    
    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let app = fileMakerApps[row]
        
        if let cell = tableView.makeView(withIdentifier: NSUserInterfaceItemIdentifier(rawValue: "AppCellID"), owner: self) as? NSTableCellView {
            
            if tableColumn?.identifier.rawValue == "PathColumnID" {
                if let appRange = app.path.range(of: ".app", options: .backwards) {
                    let truncatedPath = String(app.path[app.path.startIndex...appRange.upperBound])
                    cell.textField?.stringValue = truncatedPath
                } else {
                    cell.textField?.stringValue = app.path
                }
            } else if tableColumn?.identifier.rawValue == "VulnerabilityColumnID" {
                cell.textField?.stringValue = app.vulnerabilityStatus
            }
            
            return cell
        }
        
        return nil
    }
}
