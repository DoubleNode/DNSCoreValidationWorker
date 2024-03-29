//
//  DNSCoreValidationWorkerCodeLocation.swift
//  DoubleNode Swift Framework (DNSFramework) - DNSCoreValidationWorker
//
//  Created by Darren Ehlers.
//  Copyright © 2020 - 2016 DoubleNode.com. All rights reserved.
//

import DNSError

public extension DNSCodeLocation {
    typealias validationWorker = DNSCoreValidationWorkerCodeLocation
}
open class DNSCoreValidationWorkerCodeLocation: DNSCodeLocation {
    override open class var domainPreface: String { "com.doublenode.coreValidationWorker." }
}
