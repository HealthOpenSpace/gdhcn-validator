# HCERT Validation Analysis Against WHO Specification

## Overview
This document analyzes the current HCERT validation logic in the gdhcn-validator Python application against the [WHO Electronic Health Certificate Specification v1.1.1](https://github.com/WorldHealthOrganization/smart-trust/blob/main/input/pagecontent/hcert_spec.md) requirements. The WHO specification, based on the EU Digital Covid Certificate (EU DCC) project, defines the complete validation framework for Health Certificate Electronic Records and Transport (HCERT).

## Current API Endpoints and Their Validation Logic

### 1. `/decode/image` - QR Code Image Decoding
**Current Implementation:**
- Accepts multipart/form-data with image file
- Uses PIL and pyzbar to decode QR codes
- Performs text normalization (Unicode NFKC, whitespace removal)
- Detects format types: hcert, shlink, url, unknown
- Returns raw QR data and format classification

**Validation Aspects:**
- ✅ QR code detection and decoding
- ✅ Format detection (HC1: prefix recognition)
- ✅ Text normalization for hidden characters
- ❓ Image quality validation (not explicitly mentioned in spec)

### 2. `/decode/hcert` - HC1 String Decoding
**Current Implementation:**
```python
# Input validation
- Requires HC1: prefix
- Text normalization (Unicode NFKC, whitespace removal)
- Base45 character sanitization

# Decoding chain
1. Strip HC1: prefix
2. Base45 decode → compressed bytes
3. zlib decompress → CBOR data  
4. COSE_Sign1 decode → [protected, unprotected, payload, signature]
5. Extract HCERT from payload[-260][1]
6. Extract KID from COSE headers (label 4)
```

**Validation Against WHO HCERT Specification:**
- ✅ **Section 4.2.2**: HC1: prefix validation per transport encoding requirements
- ✅ **Section 4.2.2**: Base45 decoding with Alphanumeric Mode 2 support
- ✅ **Section 4.2.1**: zlib decompression of CWT payload
- ✅ **Section 3.1**: CBOR decoding with COSE digital signature structure (CWT)
- ✅ **Section 3.1**: COSE_Sign1 structure validation (4-element array)
- ✅ **Section 3.2.3**: Protected/unprotected header parsing with KID extraction
- ✅ **Section 3.2.7**: Payload extraction and CBOR decoding
- ✅ **Section 3.2.3**: Key Identifier (KID) extraction from headers (label 4) with precedence rules
- ❌ **Section 3.2.2**: Signature algorithm validation (ES256/PS256 requirement) - **NOT IMPLEMENTED**
- ❌ **Section 3.1**: Cryptographic signature verification - **NOT IMPLEMENTED**
- ❌ **Section 3.2.5**: Expiration time validation (exp claim, label 4) - **EXTRACTED BUT NOT VALIDATED**
- ❌ **Section 3.2.6**: Issued At validation (iat claim, label 6) - **NOT IMPLEMENTED**
- ❌ **Appendix A**: Certificate chain validation against trusted DSC list - **NOT IMPLEMENTED**
- ❌ **Appendix A**: Issuer validation against trusted framework - **NOT IMPLEMENTED**

### 3. `/extract/metadata` - Metadata Extraction
**Current Implementation:**
- Extracts KID from COSE headers (label 4)
- Extracts issuer from payload (labels: iss, 1, '1')
- Handles both direct values and base64-encoded bytes

**Validation Aspects Per WHO Specification:**
- ✅ **Section 3.2.3**: KID extraction with proper header precedence (protected > unprotected)
- ✅ **Section 3.2.3**: Multiple KID format handling (bytes → base64url, dict._b64, string)
- ✅ **Section 3.2.4**: Issuer extraction with multiple label support (iss, 1, '1')
- ❌ **Appendix A.1**: KID format validation per SHA-256 truncation specification - **NOT IMPLEMENTED**
- ❌ **Section 3.2.4**: Issuer format validation (ISO 3166-1 alpha-2) - **NOT IMPLEMENTED**

### 4. `/extract/reference` - SHLink Reference Extraction  
**Current Implementation:**
- Searches for references in hcert[5] and payload[-260][5]
- Supports multiple reference formats:
  - shlink:// with base64url JSON payload
  - base64url encoded URLs
  - plain URLs
- Handles list structures like [{'u': 'shlink://...'}]

**Validation Aspects Per WHO Specification:**
- ✅ **Section 3.2.7.1.5**: Multiple reference location support for Smart Health Links
- ✅ **Section 3.2.7.1.5**: shlink:// protocol handling per SHL specification
- ✅ Base64url decoding with padding
- ✅ JSON payload parsing for shlink://
- ❌ Reference URL validation and security checks - **NOT IMPLEMENTED**
- ❌ Encryption key validation per SHL specification - **NOT IMPLEMENTED**

## Missing WHO HCERT Specification Compliance

Based on the WHO Electronic Health Certificate Specification v1.1.1, the following critical validation components are missing:

### 1. Cryptographic Validation (Section 3.1 & 3.2.2)
**CRITICAL SECURITY GAP**
1. **Signature Verification**
   - COSE signature validation against Document Signing Certificate (DSC)
   - Algorithm validation: MUST support ES256 (primary) and PS256 (secondary)
   - Specification: Section 3.2.2 requires both algorithms MUST be implemented

2. **Certificate Chain Validation**
   - DSC validation against Signing Certificate Authority (SCA)
   - Certificate expiration checks
   - Authority Key Identifier (AKI) matching Subject Key Identifier (SKI)
   - Specification: Section 5 and Appendix A

### 2. Temporal Validation (Sections 3.2.5 & 3.2.6)
**CURRENTLY PARTIALLY IMPLEMENTED**
1. **Expiration Time Validation**
   - MUST validate 'exp' claim (label 4) against current time per Section 3.2.5
   - Verifier MUST reject expired payloads
   - Current status: Extracted but not validated

2. **Issued At Validation**
   - MUST validate 'iat' claim (label 6) per Section 3.2.6
   - MUST not predate DSC validity period
   - Current status: Not implemented

### 3. Trust Framework Validation (Appendix A)
**INFRASTRUCTURE MISSING**
1. **Key Identifier Validation**
   - KID MUST follow SHA-256 truncation format (first 8 bytes of SHA-256 fingerprint)
   - Specification: Appendix A.1
   - Verifiers MUST check all DSCs with matching KID due to potential collisions

2. **Issuer Trust Validation**
   - Validate issuer against trusted issuer list from GDHCN Trust Network Gateway
   - ISO 3166-1 alpha-2 country code validation
   - Specification: Section 3.2.4 and Appendix A

3. **Extended Key Usage Validation**
   - Certificate MUST contain appropriate EKU for HCERT type:
     - OID 1.3.6.1.4.1.1847.2021.1.1 (test)
     - OID 1.3.6.1.4.1.1847.2021.1.2 (vaccination)  
     - OID 1.3.6.1.4.1.1847.2021.1.3 (recovery)
   - Specification: Appendix A.2

### 4. Content Schema Validation (Section 3.2.7)
**BUSINESS LOGIC MISSING**
1. **HCERT Content Validation**
   - Schema validation for subclaims per Section 3.2.7.1
   - EU DCC (subclaim 1), DDCC:VS/TR validation
   - String normalization (NFC Unicode) per Section 3.2.7

2. **Transport Format Validation**
   - QR code error correction level verification (should be 'Q'/25%)
   - Base45 Alphanumeric Mode 2 compliance
   - Specification: Section 4.2.2

## WHO Specification Compliance Roadmap

### Phase 1: Critical Security Implementation (PRIORITY: HIGH)
**Target: Minimum viable security compliance**

1. **Signature Verification Implementation**
   - Add COSE signature validation using ES256/PS256 algorithms
   - Implement DSC public key extraction and signature verification
   - Reference: Section 3.1, 3.2.2
   - Estimated effort: 2-3 weeks

2. **Temporal Validation**
   - Implement expiration time validation (`exp` claim validation)
   - Add issued at time validation (`iat` claim validation)  
   - Reference: Section 3.2.5, 3.2.6
   - Estimated effort: 1 week

3. **Algorithm Compliance**
   - Validate signature algorithm is ES256 or PS256
   - Reject certificates using unsupported algorithms
   - Reference: Section 3.2.2
   - Estimated effort: 1 week

### Phase 2: Trust Framework Integration (PRIORITY: MEDIUM)
**Target: Production-ready trust validation**

1. **Certificate Chain Validation**
   - Implement DSC validation against SCA certificates
   - Add certificate expiration and AKI/SKI validation
   - Reference: Section 5, Appendix A
   - Estimated effort: 2-3 weeks

2. **Key Identifier Validation**
   - Implement SHA-256 truncation validation for KID format
   - Add collision handling for duplicate KIDs
   - Reference: Appendix A.1
   - Estimated effort: 1-2 weeks

3. **Trusted List Integration**
   - Connect to GDHCN Trust Network Gateway
   - Implement automatic DSC list updates
   - Reference: Appendix A
   - Estimated effort: 2-4 weeks

### Phase 3: Complete Specification Compliance (PRIORITY: LOW)
**Target: Full WHO specification compliance**

1. **Extended Key Usage Validation**
   - Implement EKU validation per certificate type
   - Add test/vaccination/recovery type checking
   - Reference: Appendix A.2
   - Estimated effort: 1-2 weeks

2. **Content Schema Validation**
   - Add HCERT subclaim validation (EU DCC, DDCC:VS/TR)
   - Implement Unicode NFC normalization validation
   - Reference: Section 3.2.7
   - Estimated effort: 2-3 weeks

3. **Advanced Transport Validation**
   - QR code quality and error correction validation
   - Base45 mode compliance checking
   - Reference: Section 4.2.2
   - Estimated effort: 1 week

## WHO Specification Compliance Summary

| Endpoint | Current Functionality | WHO Spec Compliance | Critical Missing Validation |
|----------|----------------------|---------------------|------------------------------|
| `/decode/image` | QR decode + format detection | ✅ **Compliant** (Section 4.2.2) | None for decoding phase |
| `/decode/hcert` | Full HC1 → COSE decode | ⚠️ **Partial** (Structure only) | **Signature verification, temporal validation** |
| `/extract/metadata` | KID + issuer extraction | ⚠️ **Partial** (Basic extraction) | **KID format validation, issuer trust validation** |
| `/extract/reference` | SHLink discovery | ✅ **Compliant** (Section 3.2.7.1.5) | SHL security validation |
| `/shlink/authorize` | PIN-based authorization | ✅ **Implementation** | Error handling improvements |
| `/shlink/fetch-fhir` | FHIR resource fetching | ✅ **Implementation** | Content validation |

### Security Risk Assessment
- **HIGH RISK**: No cryptographic signature verification (Section 3.1)
- **HIGH RISK**: No expiration time validation (Section 3.2.5)  
- **MEDIUM RISK**: No certificate chain validation (Appendix A)
- **MEDIUM RISK**: No issuer trust validation (Section 3.2.4)
- **LOW RISK**: No extended key usage validation (Appendix A.2)

### Compliance Status
- **✅ Compliant**: Transport decoding, basic structure parsing
- **⚠️ Partially Compliant**: Metadata extraction, payload decoding
- **❌ Non-Compliant**: Security validation, trust framework integration

## Implementation Priority Matrix

| Component | WHO Spec Section | Security Impact | Implementation Effort | Priority |
|-----------|------------------|-----------------|----------------------|----------|
| Signature Verification | 3.1, 3.2.2 | **CRITICAL** | High | **P0** |
| Expiration Validation | 3.2.5 | **HIGH** | Low | **P0** |
| Certificate Chain | Appendix A | **HIGH** | High | **P1** |
| KID Format Validation | Appendix A.1 | **MEDIUM** | Medium | **P1** |
| Issuer Trust Validation | 3.2.4, Appendix A | **MEDIUM** | High | **P1** |
| EKU Validation | Appendix A.2 | **LOW** | Medium | **P2** |
| Content Schema | 3.2.7 | **LOW** | High | **P2** |