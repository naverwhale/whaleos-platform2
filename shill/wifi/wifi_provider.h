// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_WIFI_PROVIDER_H_
#define SHILL_WIFI_WIFI_PROVIDER_H_

#include <map>
#include <string>
#include <vector>

#include "shill/data_types.h"
#include "shill/provider_interface.h"
#include "shill/refptr_types.h"

namespace shill {

class ByteString;
class Error;
class KeyValueStore;
class Manager;
class Metrics;
class WiFiEndpoint;
class WiFiService;

// The WiFi Provider is the holder of all WiFi Services.  It holds both
// visible (created due to an Endpoint becoming visible) and invisible
// (created due to user or storage configuration) Services.
class WiFiProvider : public ProviderInterface {
 public:
  explicit WiFiProvider(Manager* manager);
  WiFiProvider(const WiFiProvider&) = delete;
  WiFiProvider& operator=(const WiFiProvider&) = delete;

  ~WiFiProvider() override;

  // Called by Manager as a part of the Provider interface.  The attributes
  // used for matching services for the WiFi provider are the SSID, mode and
  // security parameters.
  void CreateServicesFromProfile(const ProfileRefPtr& profile) override;
  ServiceRefPtr FindSimilarService(const KeyValueStore& args,
                                   Error* error) const override;
  ServiceRefPtr GetService(const KeyValueStore& args, Error* error) override;
  ServiceRefPtr CreateTemporaryService(const KeyValueStore& args,
                                       Error* error) override;
  ServiceRefPtr CreateTemporaryServiceFromProfile(const ProfileRefPtr& profile,
                                                  const std::string& entry_name,
                                                  Error* error) override;
  void Start() override;
  void Stop() override;

  // Find a Service this Endpoint should be associated with.
  virtual WiFiServiceRefPtr FindServiceForEndpoint(
      const WiFiEndpointConstRefPtr& endpoint);

  // Find or create a Service for |endpoint| to be associated with.  This
  // method first calls FindServiceForEndpoint, and failing this, creates
  // a new Service.  It then associates |endpoint| with this service.
  virtual void OnEndpointAdded(const WiFiEndpointConstRefPtr& endpoint);

  // Called by a Device when it removes an Endpoint.  If the Provider
  // forgets a service as a result, it returns a reference to the
  // forgotten service, otherwise it returns a null reference.
  virtual WiFiServiceRefPtr OnEndpointRemoved(
      const WiFiEndpointConstRefPtr& endpoint);

  // Called by a Device when it receives notification that an Endpoint
  // has changed.  Ensure the updated endpoint still matches its
  // associated service.  If necessary re-assign the endpoint to a new
  // service, otherwise notify the associated service of the update to
  // the endpoint.
  virtual void OnEndpointUpdated(const WiFiEndpointConstRefPtr& endpoint);

  // Called by a WiFiService when it is unloaded and no longer visible.
  virtual bool OnServiceUnloaded(const WiFiServiceRefPtr& service);

  // Get the list of SSIDs for hidden WiFi services we are aware of.
  virtual ByteArrays GetHiddenSSIDList();

  // Performs some "provider_of_wifi" storage updates.
  virtual void UpdateStorage(Profile* profile);

  // Report the number of auto connectable services available to uma
  // metrics.
  void ReportAutoConnectableServices();

  // Returns number of services available for auto-connect.
  virtual int NumAutoConnectableServices();

  // Returns a list of ByteStrings representing the SSIDs of WiFi services
  // configured for auto-connect.
  std::vector<ByteString> GetSsidsConfiguredForAutoConnect();

  bool disable_vht() const { return disable_vht_; }
  void set_disable_vht(bool disable_vht) { disable_vht_ = disable_vht; }

 private:
  friend class WiFiProviderTest;

  using EndpointServiceMap = std::map<const WiFiEndpoint*, WiFiServiceRefPtr>;

  // Add a service to the service_ vector and register it with the Manager.
  WiFiServiceRefPtr AddService(const std::vector<uint8_t>& ssid,
                               const std::string& mode,
                               const std::string& security_class,
                               bool is_hidden);

  // Find a service given its properties.
  // |security| can be either a security class, or a security (security class
  // is a subset of security).
  WiFiServiceRefPtr FindService(const std::vector<uint8_t>& ssid,
                                const std::string& mode,
                                const std::string& security) const;

  // Returns a WiFiServiceRefPtr for unit tests and for down-casting to a
  // ServiceRefPtr in GetService().
  WiFiServiceRefPtr GetWiFiService(const KeyValueStore& args, Error* error);

  // Disassociate the service from its WiFi device and remove it from the
  // services_ vector.
  void ForgetService(const WiFiServiceRefPtr& service);

  void ReportRememberedNetworkCount();
  void ReportServiceSourceMetrics();

  Metrics* metrics() const;

  // Sort the internal list of services.
  void SortServices();

  Manager* manager_;

  std::vector<WiFiServiceRefPtr> services_;
  EndpointServiceMap service_by_endpoint_;

  bool running_;

  // Disable 802.11ac Very High Throughput (VHT) connections.
  bool disable_vht_;
};

}  // namespace shill

#endif  // SHILL_WIFI_WIFI_PROVIDER_H_
