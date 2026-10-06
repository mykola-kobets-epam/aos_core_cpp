/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CM_ROOTCERTIFICATES_ROOTCERTIFICATESHANDLER_HPP_
#define AOS_CM_ROOTCERTIFICATES_ROOTCERTIFICATESHANDLER_HPP_

#include <core/cm/nodeinfoprovider/itf/nodeinfoprovider.hpp>
#include <core/cm/updatemanager/itf/sender.hpp>
#include <core/common/cloudconnection/itf/cloudconnection.hpp>
#include <core/common/iamclient/itf/certhandler.hpp>
#include <core/common/tools/error.hpp>
#include <core/common/types/certificates.hpp>

namespace aos::cm::rootcertificates {

/**
 * Desired root certificates handler interface.
 */
class DesiredRootCertificatesHandlerItf {
public:
    /**
     * Destructor.
     */
    virtual ~DesiredRootCertificatesHandlerItf() = default;

    /**
     * Updates root certificates from desired unit root certificates and reports partial thumbnails
     * for updated nodes.
     *
     * @param desiredRootCerts desired unit root certificates.
     */
    virtual void UpdateRootCerts(const DesiredUnitRootCertificates& desiredRootCerts) = 0;
};

/**
 * Handles desired root certificate updates and reports unit root certificate thumbnails to the cloud.
 */
class RootCertificatesHandler : public DesiredRootCertificatesHandlerItf,
                                private cloudconnection::ConnectionListenerItf,
                                private nodeinfoprovider::NodeInfoListenerItf {
public:
    /**
     * Initializes root certificates handler.
     *
     * @param certHandler certificate handler.
     * @param nodeInfoProvider node info provider.
     * @param cloudConnection cloud connection.
     * @param sender unit root certificates sender.
     * @return Error.
     */
    Error Init(iamclient::CertHandlerItf& certHandler, nodeinfoprovider::NodeInfoProviderItf& nodeInfoProvider,
        cloudconnection::CloudConnectionItf& cloudConnection, updatemanager::SenderItf& sender);

    /**
     * Starts root certificates handler.
     *
     * @return Error.
     */
    Error Start();

    /**
     * Stops root certificates handler.
     *
     * @return Error.
     */
    Error Stop();

    /**
     * Updates root certificates from desired unit root certificates and reports partial thumbnails
     * for updated nodes.
     *
     * @param desiredRootCerts desired unit root certificates.
     */
    void UpdateRootCerts(const DesiredUnitRootCertificates& desiredRootCerts) override;

private:
    void OnConnect() override;
    void OnDisconnect() override;
    void OnNodeInfoChanged(const UnitNodeInfo& info) override;

    Error CollectNodeRootCertThumbnails(const String& nodeID, NodeRootCertificates& nodeRootCertificates);
    Error CollectUnitRootCertificates(
        const Array<StaticString<cIDLen>>& nodeIDs, bool isPartial, UnitRootCertificates& unitRootCertificates);
    Error SendAllUnitRootCertificates(bool isPartial);
    Error SendUnitRootCertificates(const UnitRootCertificates& unitRootCertificates);

    iamclient::CertHandlerItf*             mCertHandler {};
    nodeinfoprovider::NodeInfoProviderItf* mNodeInfoProvider {};
    cloudconnection::CloudConnectionItf*   mCloudConnection {};
    updatemanager::SenderItf*              mSender {};
    bool                                   mCloudConnected {};
};

} // namespace aos::cm::rootcertificates

#endif
