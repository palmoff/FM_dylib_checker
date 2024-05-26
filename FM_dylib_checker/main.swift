//
//  main.swift
//  FM_dylib_checker
//
//  Created by Alexey Dubov on 18.05.2024.
//

import Foundation


struct FileMakerApp {
    var path: String
    var identifier: String
}

    printFileMakerApps()


func printFileMakerApps() {
    
    print("App is running, please wait...")
    
    let FileMakerApps = listFileMakerApps()
    
    print("╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗")
    print("║    Vulnerability Status              │              Path                                                          ║")
    print("╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝")
    
    var answer = ""
    
    FileMakerApps.forEach { FileMakerApp in
        
        if !FileMakerApp.identifier.isEmpty
        {
                    let mybundle = Bundle(path : FileMakerApp.path)
                    let myURL = mybundle?.bundleURL
                    let name = mybundle?.object(forInfoDictionaryKey: kCFBundleNameKey as String)
                    let appName = name as? String
                    var codeRef: SecStaticCode? = nil
                    SecStaticCodeCreateWithPath(myURL! as CFURL, [], &codeRef)
            answer = verifyHardenedRuntimeAndProblematicEntitlements(applicationName: appName ?? "FileMaker", secStaticCode: codeRef!)
        }
        print("\(answer)\(FileMakerApp.path)")
    }
}

func verifyHardenedRuntimeAndProblematicEntitlements(applicationName: String, secStaticCode: SecStaticCode) -> String {
       var signingInformationOptional: CFDictionary? = nil
       if SecCodeCopySigningInformation(secStaticCode, SecCSFlags(rawValue: kSecCSDynamicInformation), &signingInformationOptional) != errSecSuccess {
           return "   ⚠️ Vulnarable, can't get signature    "
       }
       
       guard let signingInformation = signingInformationOptional else {
           return "   ⚠️ Vulnarable, empty                  "
       }

       let signingInformationDict = signingInformation as NSDictionary
       
       let signingFlagsOptional = signingInformationDict.object(forKey: "flags") as? UInt32
       
       if let signingFlags = signingFlagsOptional {
           let hardenedRuntimeFlag: UInt32 = 0x10000
         if (signingFlags & hardenedRuntimeFlag) != hardenedRuntimeFlag {
            return "   ⚠️ Vulnarable, dylib allowed          "
           }
       } else {
            return "   ⚠️ Vulnarable, Not signed             "
       }
    
       let entitlementsOptional = signingInformationDict.object(forKey: "entitlements-dict") as? NSDictionary
       guard let entitlements = entitlementsOptional else {
           return  "   ⚠️Vulnarable, No entitlements         "
       }
    
        let disableDylbkeyExists = entitlements["com.apple.security.cs.disable-library-validation"] != nil
        let allowDylibkeyExsists = entitlements["com.apple.security.cs.allow-dyld-environment-variables"] != nil

         if disableDylbkeyExists && allowDylibkeyExsists {
             return "   ⚠️ Vulnarable, dylib allowed          "
         }
       return       "   ✅ Not vulnarable                     "
   }


func listFileMakerApps() -> [FileMakerApp] {
    let FileMakerAppPaths: [String] = listFileMakerAppPaths()
    var FileMakerApps: [FileMakerApp] = []
    
    FileMakerAppPaths.forEach { FileMakerAppPath in
    
        let FileMakerFrameworkURL = URL(filePath: FileMakerAppPath)
            
            let FileMakerAppURL = FileMakerFrameworkURL.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            
            if let bundle = Bundle(url: FileMakerAppURL) {
                FileMakerApps.append(FileMakerApp(path: bundle.bundlePath, identifier: bundle.bundleIdentifier ?? ""))
            }
    }
    return FileMakerApps
}


func listFileMakerAppPaths() -> [String] {
    let fileManager = FileManager.default
    var FileMakerFrameworkSubdirectories: [String] = []
    
    func searchForFileMakerFramework(path: String, depth: Int) {
        if depth > 6 {
            return
        }
        do {
            let subdirectories = try fileManager.contentsOfDirectory(atPath: path)
            for subdirectory in subdirectories {
                let subdirectoryPath = "\(path)/\(subdirectory)"
                var isDirectory: ObjCBool = false
                if fileManager.fileExists(atPath: subdirectoryPath, isDirectory: &isDirectory) {
                    if isDirectory.boolValue {
                        if subdirectory == "DBEngine.framework" {
                            FileMakerFrameworkSubdirectories.append(subdirectoryPath)
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
    
    return FileMakerFrameworkSubdirectories
}


