# RDE Java client
This repository contains the source code for the RDE Java client library. 
The library can can be used to interact with e-passports to enroll them for RDE and retrieve secret keys from them.

## Usage
Interaction with an e-passport happens via the `RDEDocument` class.
RDEDocuments are initialized with a `BACKey` and a`CardService` object.

```kotlin
import android.nfc.Tag
import android.nfc.tech.IsoDep

import org.jmrtd.BACKey

val isoDep = IsoDep.get(tag)
val cardService = CardService.getInstance(isoDep)
val bacKey = BACKey("123456789", "111111", "111111")

val document = RDEDocument(bacKey!!)
document.init(cardService)
```

### Enrolling
To enroll an e-passport for RDE, call the `enroll` method on the `RDEDocument` object.
This takes several parameters:

```kotlin
val documentName = "My passport"
val rdeDgId = 14
val rdeDgRbLength = 223
val withSecurityData = true
val withMRZData = true
val withFaceImage = true

document.open()
val enrollmentParams = document.enroll(enrollmentDocumentName, rdeDgId, rdeDgRbLength, withSecurityData, withMRZData, withFaceImage)
document.close()
```

### Retrieving secret keys
To retrieve secret keys from an e-passport, call the `decrypt` method on the `RDEDocument` object, with the corresponding `DecryptionParameters` object.

```kotlin
document.open()
val secretKey = document.decrypt(decryptionParameters)
document.close()
```

### Key generation
Additionally, the library can be used to generate keys for RDE. This is done via the `RDEKeyGenerator` class.

```kotlin
val enrollmentParams = RDEEnrollmentParameters("...")

val keyGenerator = RDEKeyGenerator(enrollmentParams)
val key = keyGenerator.generateKey()

val secretKey = key.secretKey
val decrryptionParameters = key.decryptionParameters
```
