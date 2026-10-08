/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <memory>

#include <core/common/tools/logger.hpp>

#include "rootcertificateshandler.hpp"

namespace aos::cm::rootcertificates {

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

Error RootCertificatesHandler::Init(iamclient::CertHandlerItf& certHandler,
    nodeinfoprovider::NodeInfoProviderItf& nodeInfoProvider, cloudconnection::CloudConnectionItf& cloudConnection,
    updatemanager::SenderItf& sender)
{
    LOG_DBG() << "Init root certificates handler";

    mCertHandler      = &certHandler;
    mNodeInfoProvider = &nodeInfoProvider;
    mCloudConnection  = &cloudConnection;
    mSender           = &sender;

    return ErrorEnum::eNone;
}

Error RootCertificatesHandler::Start()
{
    LOG_DBG() << "Start root certificates handler";

    if (auto err = mNodeInfoProvider->SubscribeListener(*this); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = mCloudConnection->SubscribeListener(*this); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return ErrorEnum::eNone;
}

Error RootCertificatesHandler::Stop()
{
    LOG_DBG() << "Stop root certificates handler";

    if (auto err = mCloudConnection->UnsubscribeListener(*this); !err.IsNone() && !err.Is(ErrorEnum::eNotFound)) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = mNodeInfoProvider->UnsubscribeListener(*this); !err.IsNone() && !err.Is(ErrorEnum::eNotFound)) {
        return AOS_ERROR_WRAP(err);
    }

    mCloudConnected = false;

    return ErrorEnum::eNone;
}

void RootCertificatesHandler::UpdateRootCerts(const DesiredUnitRootCertificates& desiredRootCerts)
{
    LOG_DBG() << "Update unit root certificates";

    if (desiredRootCerts.mNodeCertificates.IsEmpty()) {
        LOG_WRN() << "No desired root certificates received";

        return;
    }

    auto updatedNodeIDs = std::make_unique<StaticArray<StaticString<cIDLen>, cMaxNumNodes>>();
    if (!updatedNodeIDs) {
        LOG_ERR() << "No memory for updated node IDs";

        return;
    }

    for (const auto& nodeRootCerts : desiredRootCerts.mNodeCertificates) {
        LOG_DBG() << "Update root certificates" << Log::Field("nodeID", nodeRootCerts.mNodeID)
                  << Log::Field("count", nodeRootCerts.mCertificates.Size());

        if (auto err = mCertHandler->UpdateRootCerts(nodeRootCerts.mNodeID, nodeRootCerts.mCertificates);
            !err.IsNone()) {
            LOG_ERR() << "Update root certificates failed" << Log::Field("nodeID", nodeRootCerts.mNodeID)
                      << Log::Field(err);
            continue;
        }

        if (auto err = updatedNodeIDs->PushBack(nodeRootCerts.mNodeID); !err.IsNone()) {
            LOG_ERR() << "Failed to collect updated node ID" << Log::Field(err);

            return;
        }
    }

    if (updatedNodeIDs->IsEmpty()) {
        return;
    }

    auto unitRootCertificates = std::make_unique<UnitRootCertificates>();
    if (!unitRootCertificates) {
        LOG_ERR() << "No memory for unit root certificates";

        return;
    }

    if (auto err = CollectUnitRootCertificates(*updatedNodeIDs, true, *unitRootCertificates); !err.IsNone()) {
        LOG_ERR() << "Collect unit root certificates failed" << Log::Field(err);

        return;
    }

    if (auto err = SendUnitRootCertificates(*unitRootCertificates); !err.IsNone()) {
        LOG_ERR() << "Send unit root certificates failed" << Log::Field(err);
    }
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

void RootCertificatesHandler::OnConnect()
{
    LOG_DBG() << "Cloud connected";

    mCloudConnected = true;

    if (auto err = SendAllUnitRootCertificates(false); !err.IsNone()) {
        LOG_ERR() << "Send unit root certificates failed" << Log::Field(err);
    }
}

void RootCertificatesHandler::OnDisconnect()
{
    LOG_DBG() << "Cloud disconnected";

    mCloudConnected = false;
}

void RootCertificatesHandler::OnNodeInfoChanged(const UnitNodeInfo& info)
{
    LOG_DBG() << "Node info changed" << Log::Field("id", info.mNodeID) << Log::Field("type", info.mNodeType)
              << Log::Field("state", info.mState) << Log::Field("isConnected", info.mIsConnected);

    if (!mCloudConnected) {
        return;
    }

    auto nodeIDs = std::make_unique<StaticArray<StaticString<cIDLen>, cMaxNumNodes>>();
    if (!nodeIDs) {
        LOG_ERR() << "No memory for node IDs";

        return;
    }

    if (auto err = nodeIDs->PushBack(info.mNodeID); !err.IsNone()) {
        LOG_ERR() << "Failed to collect node ID" << Log::Field(err);

        return;
    }

    auto unitRootCertificates = std::make_unique<UnitRootCertificates>();
    if (!unitRootCertificates) {
        LOG_ERR() << "No memory for unit root certificates";

        return;
    }

    if (auto err = CollectUnitRootCertificates(*nodeIDs, true, *unitRootCertificates); !err.IsNone()) {
        LOG_ERR() << "Collect unit root certificates failed" << Log::Field(err);

        return;
    }

    if (auto err = SendUnitRootCertificates(*unitRootCertificates); !err.IsNone()) {
        LOG_ERR() << "Send unit root certificates failed" << Log::Field(err);
    }
}

Error RootCertificatesHandler::CollectNodeRootCertFingerprints(
    const String& nodeID, NodeRootCertificates& nodeRootCertificates)
{
    if (auto err = nodeRootCertificates.mNodeID.Assign(nodeID); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = mCertHandler->GetRootCerts(nodeID, nodeRootCertificates.mSHA256Fingerprints); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return ErrorEnum::eNone;
}

Error RootCertificatesHandler::CollectUnitRootCertificates(
    const Array<StaticString<cIDLen>>& nodeIDs, bool isPartial, UnitRootCertificates& unitRootCertificates)
{
    unitRootCertificates.mIsPartial = isPartial;
    unitRootCertificates.mNodeCertificates.Clear();

    for (const auto& nodeID : nodeIDs) {
        if (auto err = unitRootCertificates.mNodeCertificates.EmplaceBack(); !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }

        if (auto err = CollectNodeRootCertFingerprints(nodeID, unitRootCertificates.mNodeCertificates.Back());
            !err.IsNone()) {
            LOG_WRN() << "Can't get root cert fingerprints" << Log::Field("nodeID", nodeID) << Log::Field(err);

            unitRootCertificates.mNodeCertificates.PopBack();
            continue;
        }
    }

    return ErrorEnum::eNone;
}

Error RootCertificatesHandler::SendAllUnitRootCertificates(bool isPartial)
{
    auto nodeIDs = std::make_unique<StaticArray<StaticString<cIDLen>, cMaxNumNodes>>();
    if (!nodeIDs) {
        return AOS_ERROR_WRAP(ErrorEnum::eNoMemory);
    }

    if (auto err = mNodeInfoProvider->GetAllNodeIDs(*nodeIDs); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (nodeIDs->IsEmpty()) {
        return ErrorEnum::eNone;
    }

    auto unitRootCertificates = std::make_unique<UnitRootCertificates>();
    if (!unitRootCertificates) {
        return AOS_ERROR_WRAP(ErrorEnum::eNoMemory);
    }

    if (auto err = CollectUnitRootCertificates(*nodeIDs, isPartial, *unitRootCertificates); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return SendUnitRootCertificates(*unitRootCertificates);
}

Error RootCertificatesHandler::SendUnitRootCertificates(const UnitRootCertificates& unitRootCertificates)
{
    if (unitRootCertificates.mNodeCertificates.IsEmpty()) {
        return ErrorEnum::eNone;
    }

    LOG_DBG() << "Send unit root certificates" << Log::Field("isPartial", unitRootCertificates.mIsPartial)
              << Log::Field("count", unitRootCertificates.mNodeCertificates.Size());

    return mSender->SendUnitRootCertificates(unitRootCertificates);
}

} // namespace aos::cm::rootcertificates
