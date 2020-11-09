# Encryption Component

encryption-component is a Kotlin library for dealing with token providers encryption fields

## Installation

Add this dependency into your build.gradle

```bash
implementation 'com.veritran.tokenization:encryption-component:0.0.1@jar'
```

## Usage

```java
Use one of these actions ( wip: in the future you must use only the Provider class):

	CreateJWE
	CreateSymmetricJWE
	DecryptMDESPayload
	DecryptMessage
	EncryptMessage
	SignMessage
	UnwrapJWE
	VerifySignature
```

## Upload new verdion into nexus 
```bash
  cd encryption-component
 ./gradlew publish -PnexusUser=$NEXUS_USER -PnexusPassword=$NEXUS_PASSWORD
```
