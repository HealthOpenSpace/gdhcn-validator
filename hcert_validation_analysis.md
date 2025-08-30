# HCERT Validation Analysis

## Overview
This document analyzes the current HCERT validation logic in the gdhcn-validator Python application against common HCERT specification requirements.

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

**Validation Against Typical HCERT Requirements:**
- ✅ HC1: prefix validation
- ✅ Base45 decoding with character validation
- ✅ zlib decompression
- ✅ CBOR decoding with tag unwrapping (Tag 18 = COSE_Sign1)
- ✅ COSE_Sign1 structure validation (4-element array)
- ✅ Protected/unprotected header parsing
- ✅ Payload extraction and CBOR decoding
- ✅ KID (Key Identifier) extraction from headers
- ❓ Signature verification (not implemented)
- ❓ Certificate chain validation (not implemented)
- ❓ Expiration time validation (extracted but not validated)
- ❓ Issuer validation against trusted list (not implemented)

### 3. `/extract/metadata` - Metadata Extraction
**Current Implementation:**
- Extracts KID from COSE headers (label 4)
- Extracts issuer from payload (labels: iss, 1, '1')
- Handles both direct values and base64-encoded bytes

**Validation Aspects:**
- ✅ KID extraction with proper header precedence (protected > unprotected)
- ✅ Multiple KID format handling (bytes → base64url, dict._b64, string)
- ✅ Issuer extraction with multiple label support
- ❓ KID format validation per spec requirements
- ❓ Issuer format validation

### 4. `/extract/reference` - SHLink Reference Extraction  
**Current Implementation:**
- Searches for references in hcert[5] and payload[-260][5]
- Supports multiple reference formats:
  - shlink:// with base64url JSON payload
  - base64url encoded URLs
  - plain URLs
- Handles list structures like [{'u': 'shlink://...'}]

**Validation Aspects:**
- ✅ Multiple reference location support
- ✅ shlink:// protocol handling
- ✅ Base64url decoding with padding
- ✅ JSON payload parsing for shlink://
- ❓ Reference URL validation
- ❓ Encryption key validation

## Missing HCERT Validation Components

Based on common HCERT specifications, the following validation aspects may be missing:

### Cryptographic Validation
1. **Signature Verification**
   - COSE signature validation against public key
   - ECDSA/EdDSA algorithm support per spec

2. **Certificate Chain Validation**
   - Certificate chain verification
   - Root CA validation
   - Certificate expiration checks

### Temporal Validation
1. **Token Expiration**
   - Validate 'exp' claim (label 4) against current time
   - Handle timezone considerations

2. **Not Before Validation**
   - Validate 'nbf' claim if present

### Content Validation
1. **Schema Validation**
   - HCERT content schema validation per specification
   - Required field presence
   - Field format validation

2. **Business Rule Validation**
   - Country-specific validation rules
   - Health certificate type validation

### Trust Framework
1. **Issuer Validation**
   - Validate issuer against trusted issuer list
   - Country code validation

2. **Key Identifier Validation**
   - KID format per specification requirements
   - Key resolution from trust framework

## Recommendations for Specification Compliance

1. **Immediate Actions**
   - Review HCERT specification sections 3.2.3 (Key Identifier) and related
   - Implement signature verification for critical validation
   - Add expiration time validation

2. **Medium Priority**
   - Add certificate chain validation
   - Implement schema validation for HCERT content
   - Add issuer trust list validation

3. **Long Term**
   - Implement comprehensive business rules
   - Add support for revocation lists
   - Performance optimization for validation pipeline

## API Endpoint Summary

| Endpoint | Current Functionality | Spec Compliance | Missing Validation |
|----------|----------------------|-----------------|-------------------|
| `/decode/image` | QR decode + format detection | ✅ Good | Image quality checks |
| `/decode/hcert` | Full HC1 → COSE decode | ✅ Structure only | Signature, expiration |
| `/extract/metadata` | KID + issuer extraction | ✅ Basic | Format validation |
| `/extract/reference` | SHLink discovery | ✅ Good | URL validation |
| `/shlink/authorize` | PIN-based authorization | ✅ Implementation | Error handling |
| `/shlink/fetch-fhir` | FHIR resource fetching | ✅ Implementation | Content validation |

## Next Steps

1. Obtain full HCERT specification access
2. Identify specific validation requirements per section
3. Prioritize implementation based on security criticality
4. Add comprehensive test cases for validation scenarios