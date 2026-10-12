// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MedicalRecords
/// @notice Stores only CID + SHA-256 of each record. Files live encrypted on IPFS.
contract MedicalRecords {
    struct Record {
        address patient;
        string name;
        string cid;        // IPFS CID of the ENCRYPTED file
        bytes32 fileHash;  // SHA-256 of the ORIGINAL file
        uint256 uploadedAt;
    }

    address public immutable logger; // backend wallet allowed to write access logs
    uint256 public recordCount;
    mapping(uint256 => Record) public records;
    // recordId => doctor => unix expiry (0 = no access / revoked)
    mapping(uint256 => mapping(address => uint256)) public accessExpiry;

    event RecordUploaded(uint256 indexed id, address indexed patient, string cid, bytes32 fileHash, uint256 timestamp);
    event AccessGranted(uint256 indexed id, address indexed patient, address indexed doctor, uint256 expiresAt);
    event AccessRevoked(uint256 indexed id, address indexed patient, address indexed doctor);
    event RecordAccessed(uint256 indexed id, address indexed user, bool granted, bool integrityOk, uint256 timestamp);

    modifier onlyPatient(uint256 id) {
        require(records[id].patient == msg.sender, "Only the patient");
        _;
    }

    constructor() {
        logger = msg.sender;
    }

    function uploadRecord(string calldata name, string calldata cid, bytes32 fileHash) external returns (uint256 id) {
        require(bytes(cid).length > 0, "CID required");
        id = ++recordCount;
        records[id] = Record(msg.sender, name, cid, fileHash, block.timestamp);
        emit RecordUploaded(id, msg.sender, cid, fileHash, block.timestamp);
    }

    /// @param duration seconds of access; 0 = no expiry
    function grantAccess(uint256 id, address doctor, uint256 duration) external onlyPatient(id) {
        require(doctor != address(0) && doctor != msg.sender, "Invalid doctor");
        uint256 expiresAt = duration == 0 ? type(uint64).max : block.timestamp + duration;
        accessExpiry[id][doctor] = expiresAt;
        emit AccessGranted(id, msg.sender, doctor, expiresAt);
    }

    function revokeAccess(uint256 id, address doctor) external onlyPatient(id) {
        accessExpiry[id][doctor] = 0;
        emit AccessRevoked(id, msg.sender, doctor);
    }

    function checkAccess(uint256 id, address user) public view returns (bool) {
        address patient = records[id].patient;
        if (patient == address(0)) return false;
        if (user == patient) return true;
        return accessExpiry[id][user] > block.timestamp;
    }

    /// @notice Called by the backend after every open attempt (granted or denied).
    function logAccess(uint256 id, address user, bool granted, bool integrityOk) external {
        require(msg.sender == logger, "Only backend logger");
        require(records[id].patient != address(0), "No such record");
        emit RecordAccessed(id, user, granted, integrityOk, block.timestamp);
    }
}
