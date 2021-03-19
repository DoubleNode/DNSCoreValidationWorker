//
//  WKRCoreValidationWorker.swift
//  DoubleNode Swift Framework (DNSFramework) - DNSCoreValidationWorker
//
//  Created by Darren Ehlers.
//  Copyright © 2020 - 2016 DoubleNode.com. All rights reserved.
//

import DNSBlankWorkers
import DNSCore
import DNSCorePasswordStrengthWorker
import DNSCrashWorkers
import DNSError
import DNSProtocols
import Foundation

open class WKRCoreValidationWorker: WKRBlankValidationWorker
{
    public enum Regex {
        static let email = "[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,64}"
        static let phone = "^[0-9]{10}$"
    }

    public var emailRegex: String = Regex.email
    public var phoneRegex: String = Regex.phone

    public var passwordStrengthWorker: PTCLPasswordStrength_Protocol = WKRCrashPasswordStrengthWorker()

    public required init() {
        super.init()
        self.commonInit()
    }
    public required init(nextWorker: PTCLValidation_Protocol) {
        super.init(nextWorker: nextWorker)
        self.commonInit()
    }
    func commonInit() {
        self.minimumBirthdateAge = -1
        self.maximumBirthdateAge = -1
        
        self.minimumHandleLength = 6
        self.maximumHandleLength = 80
        
        self.minimumNameLength = 2
        self.maximumNameLength = 250
        
        self.minimumNumberValue = -1
        self.maximumNumberValue = -1
        
        self.minimumPercentageValue = -1
        self.maximumPercentageValue = -1
        
        self.minimumPhoneLength = 10
        self.maximumPhoneLength = 10
        
        self.minimumUnsignedNumberValue = -1
        self.maximumUnsignedNumberValue = -1
    }

    // MARK: - Business Logic / Single Item CRUD
    override open func doValidateBirthdate(for birthdate: Date) throws -> DNSError? {
        return nil
    }
    override open func doValidateEmail(for email: String) throws -> DNSError? {
        guard !email.isEmpty else {
            return PTCLValidationError
                .noValue(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard email.dnsCheck(regEx: self.emailRegex) else {
            return PTCLValidationError
                .invalid(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func doValidateHandle(for handle: String) throws -> DNSError? {
        guard self.minimumHandleLength == -1 ||
                handle.count >= self.minimumHandleLength else {
            return PTCLValidationError
                .tooShort(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard self.maximumHandleLength == -1 ||
                handle.count <= self.maximumHandleLength else {
            return PTCLValidationError
                .tooLong(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func doValidateName(for name: String) throws -> DNSError? {
        guard self.minimumHandleLength == -1 ||
                name.count >= self.minimumNameLength else {
            return PTCLValidationError
                .tooShort(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard self.maximumHandleLength == -1 ||
                name.count <= self.maximumNameLength else {
            return PTCLValidationError
                .tooLong(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func doValidateNumber(for number: String) throws -> DNSError? {
        return nil
    }
    override open func doValidatePassword(for password: String) throws -> DNSError? {
        let strength = try! self.passwordStrengthWorker.doCheckPasswordStrength(for: password)
        guard strength.rawValue >= requiredPasswordStrength.rawValue else {
            return PTCLValidationError
                .tooWeak(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func doValidatePercentage(for percentage: String) throws -> DNSError? {
        return nil
    }
    override open func doValidatePhone(for phone: String) throws -> DNSError? {
        guard !phone.isEmpty else {
            return PTCLValidationError
                .noValue(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard self.minimumPhoneLength == -1 ||
                phone.count >= self.minimumPhoneLength else {
            return PTCLValidationError
                .tooShort(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard self.maximumPhoneLength == -1 ||
                phone.count <= self.maximumPhoneLength else {
            return PTCLValidationError
                .tooLong(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard phone.dnsCheck(regEx: self.phoneRegex) else {
            return PTCLValidationError
                .invalid(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func doValidateSearch(for search: String) throws -> DNSError? {
        guard !search.isEmpty else {
            return PTCLValidationError
                .noValue(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func doValidateState(for state: String) throws -> DNSError? {
        guard !state.isEmpty else {
            return PTCLValidationError
                .noValue(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard state.count >= 2 else {
            return PTCLValidationError
                .tooShort(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard state.count <= 2 else {
            return PTCLValidationError
                .tooLong(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func doValidateUnsignedNumber(for number: String) throws -> DNSError? {
        return nil
    }
}
