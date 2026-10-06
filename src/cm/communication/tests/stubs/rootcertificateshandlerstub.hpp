/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CM_COMMUNICATION_TESTS_STUBS_ROOTCERTIFICATESHANDLERSTUB_HPP_
#define AOS_CM_COMMUNICATION_TESTS_STUBS_ROOTCERTIFICATESHANDLERSTUB_HPP_

#include <cm/rootcertificates/rootcertificateshandler.hpp>

namespace aos::cm::rootcertificates {

/**
 * Desired root certificates handler stub.
 */
class DesiredRootCertificatesHandlerStub : public DesiredRootCertificatesHandlerItf {
public:
    void UpdateRootCerts(const DesiredUnitRootCertificates& desiredRootCerts) override
    {
        mDesiredRootCerts      = desiredRootCerts;
        mUpdateRootCertsCalled = true;
    }

    bool                        mUpdateRootCertsCalled {};
    DesiredUnitRootCertificates mDesiredRootCerts;
};

} // namespace aos::cm::rootcertificates

#endif
