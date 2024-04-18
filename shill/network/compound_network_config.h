// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NETWORK_COMPOUND_NETWORK_CONFIG_H_
#define SHILL_NETWORK_COMPOUND_NETWORK_CONFIG_H_

#include <memory>
#include <string>
#include <string_view>

#include "shill/network/network_config.h"

namespace shill {

// An object to store NetworkConfig from various sources and merge them into a
// combined config that will be applied to the network.
class CompoundNetworkConfig {
 public:
  explicit CompoundNetworkConfig(std::string_view logging_tag);
  CompoundNetworkConfig(const CompoundNetworkConfig&) = delete;
  CompoundNetworkConfig& operator=(const CompoundNetworkConfig&) = delete;
  ~CompoundNetworkConfig();

  // Return the combined NetworkConfig.
  const NetworkConfig& Get() const;
  // Interface for supporting Network::GetSavedIPConfig before it get
  // deprecated. Also see comment of the mentioned function.
  const NetworkConfig* GetLegacySavedIPConfig() const;
  // Return true if the IPv6 address is from SLAAC.
  bool HasSLAAC();

  void Clear();
  // Setters of NetworkConfig from various sources. Returns true if it results
  // in a change of the combined NetworkConfig.
  bool SetFromStatic(const NetworkConfig& config);
  bool SetFromSLAAC(std::unique_ptr<NetworkConfig> config);
  bool SetFromDHCP(std::unique_ptr<NetworkConfig> config);
  bool SetFromLinkProtocol(std::unique_ptr<NetworkConfig> config);

  // TODO(b/269401899): Remove these temporary accessors.
  const NetworkConfig& GetStatic() { return static_network_config_; }
  const NetworkConfig* GetLinkProtocol() {
    return link_protocol_network_config_.get();
  }

 private:
  friend std::ostream& operator<<(std::ostream& stream,
                                  const CompoundNetworkConfig& config);

  // Recalculate the combined NetworkConfig. Returns true if the value changed.
  bool Recalculate();

  // The technology-specific network configuration. Currently only used by
  // cellular and VPN.
  std::unique_ptr<NetworkConfig> link_protocol_network_config_;

  // The network configuration received from DHCPv4.
  std::unique_ptr<NetworkConfig> dhcp_network_config_;

  // The network configuration received from SLAAC.
  std::unique_ptr<NetworkConfig> slaac_network_config_;

  // The static NetworkConfig from the associated Service.
  NetworkConfig static_network_config_;

  // The combined NetworkConfig that will be used to configure the network.
  // Generated by Recalculate() based on various input NetworkConfigs. Will
  // never be nullptr. Only using a pointer here to avoid unnecessary copying.
  std::unique_ptr<NetworkConfig> combined_network_config_;

  // A header tag to use in LOG statement for identifying the corresponding
  // Network connection.
  std::string logging_tag_;
};

std::ostream& operator<<(std::ostream& stream,
                         const CompoundNetworkConfig& config);

}  // namespace shill

#endif  // SHILL_NETWORK_COMPOUND_NETWORK_CONFIG_H_