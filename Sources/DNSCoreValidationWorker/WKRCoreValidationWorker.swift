//
//  WKRCoreValidationWorker.swift
//  DoubleNode Core - DNSCoreValidationWorker
//
//  Created by Darren Ehlers on 2019/08/12.
//  Copyright © 2019 - 2016 Darren Ehlers and DoubleNode, LLC. All rights reserved.
//

import DNSBlankWorkers
import DNSCorePasswordStrengthWorker
import DNSCrashWorkers
import DNSProtocols
import Foundation

open class WKRCoreValidationWorker: WKRBlankValidationWorker
{
    public var passwordStrengthWorker: PTCLPasswordStrength_Protocol = WKRCrashPasswordStrengthWorker.init()

    // MARK: - Business Logic / Single Item CRUD
    override open func doValidateBirthdate(for birthdate: Date,
                                           with progress: PTCLProgressBlock?,
                                           and block: PTCLValidationBlockVoidBoolDNSError?) throws {
    }

    override open func doValidateEmail(for email: String,
                                       with progress: PTCLProgressBlock?,
                                       and block: PTCLValidationBlockVoidBoolDNSError?) throws {
    }

    override open func doValidateHandle(for handle: String,
                                        with progress: PTCLProgressBlock?,
                                        and block: PTCLValidationBlockVoidBoolDNSError?) throws {
    }

    override open func doValidateName(for name: String,
                                      with progress: PTCLProgressBlock?,
                                      and block: PTCLValidationBlockVoidBoolDNSError?) throws {
    }
    
    override open func doValidateNumber(for number: String,
                                        with progress: PTCLProgressBlock?,
                                        and block: PTCLValidationBlockVoidBoolDNSError?) throws {
    }
                                      
    override open func doValidatePassword(for password: String,
                                          with progress: PTCLProgressBlock?,
                                          and block: PTCLValidationBlockVoidBoolDNSError?) throws {
        let strength = try! self.passwordStrengthWorker.doCheckPasswordStrength(for: password)
        guard strength.rawValue >= requiredPasswordStrength.rawValue else {
            let error = PTCLValidationError.tooWeak(domain: "com.doublenode.\(type(of: self))",
                file: "\(#file)",
                line: "\(#line)",
                method: "\(#function)")
            block?(false, error)
            return
        }
        
        block?(true, nil)
    }

    override open func doValidatePercentage(for percentage: String,
                                            with progress: PTCLProgressBlock?,
                                            and block: PTCLValidationBlockVoidBoolDNSError?) throws {
    }

    override open func doValidatePhone(for phone: String,
                                       with progress: PTCLProgressBlock?,
                                       and block: PTCLValidationBlockVoidBoolDNSError?) throws {
    }

    override open func doValidateSearch(for search: String,
                                        with progress: PTCLProgressBlock?,
                                        and block: PTCLValidationBlockVoidBoolDNSError?) throws {
    }

    override open func doValidateState(for state: String,
                                       with progress: PTCLProgressBlock?,
                                       and block: PTCLValidationBlockVoidBoolDNSError?) throws {
    }

    override open func doValidateUnsignedNumber(for number: String,
                                                with progress: PTCLProgressBlock?,
                                                and block: PTCLValidationBlockVoidBoolDNSError?) throws {
    }
}