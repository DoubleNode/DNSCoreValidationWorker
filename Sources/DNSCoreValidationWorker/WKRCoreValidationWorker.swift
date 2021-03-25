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
    public var passwordStrengthWorker: PTCLPasswordStrength_Protocol = WKRCrashPasswordStrengthWorker()

    // MARK: - Business Logic / Single Item CRUD
    override open func doValidateBirthdate(for birthdate: Date?,
                                           with config: PTCLValidationBirthdateConfig) throws -> DNSError? {
        guard let birthdate = birthdate else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
//        guard config.minimumAge == nil || number >= config.minimumAge! else {
//            return PTCLValidationError
//                .tooLow(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
//        guard config.maximumAge == nil || number <= config.maximumAge! else {
//            return PTCLValidationError
//                .tooHigh(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
        return nil
    }
    override open func doValidateDate(for date: Date?,
                                      with config: PTCLValidationDateConfig) throws -> DNSError? {
        guard let date = date else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
//        guard config.minimum == nil || number >= config.minimum! else {
//            return PTCLValidationError
//                .tooLow(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
//        guard config.maximum == nil || number <= config.maximum! else {
//            return PTCLValidationError
//                .tooHigh(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
        return nil
    }
    override open func doValidateEmail(for email: String?,
                                       with config: PTCLValidationEmailConfig) throws -> DNSError? {
        guard let email = email else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !email.isEmpty else {
            return PTCLValidationError
                .required(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || email.dnsCheck(regEx: config.regex!) else {
            return PTCLValidationError
                .invalid(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func doValidateHandle(for handle: String?,
                                        with config: PTCLValidationHandleConfig) throws -> DNSError? {
        guard let handle = handle else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !handle.isEmpty else {
            return PTCLValidationError
                .required(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || handle.count >= config.minimumLength! else {
            return PTCLValidationError
                .tooShort(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || handle.count <= config.maximumLength! else {
            return PTCLValidationError
                .tooLong(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || handle.dnsCheck(regEx: config.regex!) else {
            return PTCLValidationError
                .invalid(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func doValidateName(for name: String?,
                                      with config: PTCLValidationNameConfig) throws -> DNSError? {
        guard let name = name else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !name.isEmpty else {
            return PTCLValidationError
                .required(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || name.count >= config.minimumLength! else {
            return PTCLValidationError
                .tooShort(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || name.count <= config.maximumLength! else {
            return PTCLValidationError
                .tooLong(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || name.dnsCheck(regEx: config.regex!) else {
            return PTCLValidationError
                .invalid(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func doValidateNumber(for number: String?,
                                        with config: PTCLValidationNumberConfig) throws -> DNSError? {
        guard let number = number else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
//        guard config.minimum == nil || number >= config.minimum! else {
//            return PTCLValidationError
//                .tooLow(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
//        guard config.maximum == nil || number <= config.maximum! else {
//            return PTCLValidationError
//                .tooHigh(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
        return nil
    }
    override open func doValidatePassword(for password: String?,
                                          with config: PTCLValidationPasswordConfig) throws -> DNSError? {
        guard let password = password else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !password.isEmpty else {
            return PTCLValidationError
                .required(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || password.count >= config.minimumLength! else {
            return PTCLValidationError
                .tooShort(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || password.count <= config.maximumLength! else {
            return PTCLValidationError
                .tooLong(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        let strength = try! self.passwordStrengthWorker.doCheckPasswordStrength(for: password)
        guard strength.rawValue >= config.strength.rawValue else {
            return PTCLValidationError
                .tooWeak(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func doValidatePercentage(for percentage: String?,
                                            with config: PTCLValidationPercentageConfig) throws -> DNSError? {
        guard let percentage = percentage else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
//        guard config.minimum == nil || number >= config.minimum! else {
//            return PTCLValidationError
//                .tooLow(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
//        guard config.maximum == nil || number <= config.maximum! else {
//            return PTCLValidationError
//                .tooHigh(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
        return nil
    }
    override open func doValidatePhone(for phone: String?,
                                       with config: PTCLValidationPhoneConfig) throws -> DNSError? {
        guard let phone = phone else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !phone.isEmpty else {
            return PTCLValidationError
                .required(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || phone.count >= config.minimumLength! else {
            return PTCLValidationError
                .tooShort(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || phone.count <= config.maximumLength! else {
            return PTCLValidationError
                .tooLong(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || phone.dnsCheck(regEx: config.regex!) else {
            return PTCLValidationError
                .invalid(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func doValidateSearch(for search: String?,
                                        with config: PTCLValidationSearchConfig) throws -> DNSError? {
        guard let search = search else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !search.isEmpty else {
            return PTCLValidationError
                .required(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || search.count >= config.minimumLength! else {
            return PTCLValidationError
                .tooShort(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || search.count <= config.maximumLength! else {
            return PTCLValidationError
                .tooLong(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || search.dnsCheck(regEx: config.regex!) else {
            return PTCLValidationError
                .invalid(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func doValidateState(for state: String?,
                                       with config: PTCLValidationStateConfig) throws -> DNSError? {
        guard let state = state else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard !config.required || !state.isEmpty else {
            return PTCLValidationError
                .required(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.minimumLength == nil || state.count >= config.minimumLength! else {
            return PTCLValidationError
                .tooShort(fieldName: config.fieldName,
                          DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.maximumLength == nil || state.count <= config.maximumLength! else {
            return PTCLValidationError
                .tooLong(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        guard config.regex == nil || state.dnsCheck(regEx: config.regex!) else {
            return PTCLValidationError
                .invalid(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
        return nil
    }
    override open func doValidateUnsignedNumber(for number: String?,
                                                with config: PTCLValidationUnsignedNumberConfig) throws -> DNSError? {
        guard let number = number else {
            return PTCLValidationError
                .noValue(fieldName: config.fieldName,
                         DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
        }
//        guard config.minimum == nil || number >= config.minimum! else {
//            return PTCLValidationError
//                .tooLow(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
//        guard config.maximum == nil || number <= config.maximum! else {
//            return PTCLValidationError
//                .tooHigh(DNSCoreValidationWorkerCodeLocation(self, "\(#file),\(#line),\(#function)"))
//        }
        return nil
    }
}
