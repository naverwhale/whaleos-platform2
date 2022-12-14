// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOD_STORAGE_H_
#define BIOD_BIOD_STORAGE_H_

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include <base/callback.h>
#include <base/files/file_path.h>
#include <brillo/secure_blob.h>
#include <base/values.h>
#include <brillo/scoped_umask.h>

#include "biod/biometrics_manager.h"
#include "biod/biometrics_manager_record.h"

namespace biod {

// Version of the record format.
constexpr int kRecordFormatVersion = 2;
constexpr int kRecordFormatVersionNoValidationValue = 1;

class BiodStorageInterface {
 public:
  struct RecordMetadata {
    /** Record file's scheme version. */
    int record_format_version;
    /** Record/fingerprint-template's UUID. */
    std::string record_id;
    /** Sanitized user session ID. */
    std::string user_id;
    /** User supplied description of finger. */
    std::string label;
    /** Positive match secrect validation value. */
    std::vector<uint8_t> validation_val;
  };

  struct Record {
    RecordMetadata metadata;
    // "data" is base64 encoded.
    std::string data;
  };

  struct ReadRecordResult {
    std::vector<Record> valid_records;
    std::vector<Record> invalid_records;
  };

  virtual ~BiodStorageInterface() = default;

  virtual void SetRootPathForTesting(const base::FilePath& root_path) = 0;
  virtual base::FilePath GetRecordFilename(
      const BiometricsManagerRecord& record) = 0;
  virtual bool WriteRecord(const BiometricsManagerRecord& record,
                           base::Value data) = 0;
  virtual ReadRecordResult ReadRecords(
      const std::unordered_set<std::string>& user_ids) = 0;
  virtual ReadRecordResult ReadRecordsForSingleUser(
      const std::string& user_id) = 0;
  virtual bool DeleteRecord(const std::string& user_id,
                            const std::string& record_id) = 0;
  virtual void set_allow_access(bool allow_access) = 0;
};

class BiodStorage : public BiodStorageInterface {
 public:
  // Constructor sets the file path to be
  // /run/daemon-store/biod/<user_id>/CrosFpBiometricsManager/<record_id>,
  // which is bound to
  // /home/root/<user_id>/biod/CrosFpBiometricsManager/<record_id>.
  explicit BiodStorage(const std::string& biometrics_manager_name);

  // Set root path to a different path for testing purpose only.
  void SetRootPathForTesting(const base::FilePath& root_path) override;

  /**
   * Get the file name for a given record. Intended to be used for testing.
   *
   * @param record
   * @return Full path on success. Empty path on failure.
   */
  base::FilePath GetRecordFilename(
      const BiometricsManagerRecord& record) override;

  // Write one record to file in per user stateful. This is called whenever
  // we enroll a new record.
  bool WriteRecord(const BiometricsManagerRecord& record,
                   base::Value data) override;

  // Read validation value from |record_dictionary| and store in |output|.
  static std::unique_ptr<std::vector<uint8_t>> ReadValidationValueFromRecord(
      int record_format_version,
      const base::Value& record_dictionary,
      const base::FilePath& record_path);

  // Read all records from file for all users in the set. Called whenever biod
  // starts or when a new user logs in.
  ReadRecordResult ReadRecords(
      const std::unordered_set<std::string>& user_ids) override;

  // Read all records from disk for a single user. Uses a file enumerator to
  // enumerate through all record files. Called whenever biod starts or when
  // a new user logs in.
  ReadRecordResult ReadRecordsForSingleUser(
      const std::string& user_id) override;

  // Delete one record file. User will be able to do this via UI. True if
  // this record does not exist on disk.
  bool DeleteRecord(const std::string& user_id,
                    const std::string& record_id) override;

  // Generate a uuid with guid.h for each record. Uuid is 128 bit number,
  // which is then turned into a string of format
  // xxxxxxxx_xxxx_xxxx_xxxx_xxxxxxxxxxxx, where x is a lowercase hex number.
  static std::string GenerateNewRecordId();

  // Set the |allow_access_| which determines whether the backing storage
  // location can be accessed or not. Depending on the mounting mechanism and
  // namespace restrictions, the mounts might not be visible until after
  // certain points of the user flow (like successful login) are complete.
  void set_allow_access(bool allow_access) override {
    allow_access_ = allow_access;
  }

 private:
  base::FilePath root_path_;
  std::string biometrics_manager_name_;
  bool allow_access_;
};
}  // namespace biod

#endif  // BIOD_BIOD_STORAGE_H_
