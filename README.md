# mls-rs uniffi for mls-rs
This moves our adaptation of the uniffi crati in mls-rs (https://github.com/germ-mark/mls-rs)
into its own indpendent repo so we can tailor this more closely for our needs
and maintain a lighter fork of mls-rs.

# iOS XCFramework
Build toolchain to generate a XCFramework for mls-rs for an iOS app, using uniffi to generate bindings

# Scripted
1. Ensure you add the ios targets to Rust
2. the script at `scripts/buildIos.swift` automates the following steps

# Post-script adjustments
1. Uniffi also complains that it is unable to find swift format, but we can just run `swift format` on the output to lint it
2. (Synthesized) Conformance to `Codable, Sendable` should be declared in the file where `KeyPackageData` is declared, so we should edit the generated header file to add the conformances. To help remind us, there is a test that will fail if KeyPackageData is not marked Codable
3. We also need MLSMember conformance to Equatable 


# Manual Steps:
(preamble - run once)
Add ios targets to Rust:
```
rustup target add aarch64-apple-ios-sim aarch64-apple-ios x86_64-apple-ios
```

(following steps are run from this crate's directory, within the mls-rs workspace)
1. Build the library
```
cargo build
```

2. Generate the bindings 
```
cargo run -p uniffi-bindgen --bin uniffi-bindgen \
	generate --library ./target/debug/libmls_rs_uniffi_ios.dylib --language swift \
	--out-dir ./bindings
```

3. Build for Swift:
We need iOS on arm, iOS simulator, and the x86_64 target for XCode Cloud

Also may need to set env `IPHONEOS_DEPLOYMENT_TARGET` to 17.0 as we depend on
that version of CryptoKit
```
cargo build --release --target=aarch64-apple-ios-sim && \ 
cargo build --release --target=aarch64-apple-ios && \
cargo build --release --target=x86_64-apple-ios
```

4. Create XCFramework
first rename `bindings/[project name]FFI.modulemap` to `bindings/module.modulemap`:
```
mv bindings/mls_rs_uniffi_iosFFI.modulemap bindings/module.modulemap
```


Then package the xcframework:
```
 xcodebuild -create-xcframework \
 	-library ./target/aarch64-apple-ios-sim/release/libmls_rs_uniffi_ios.a -headers ./bindings \
 	-library ./target/aarch64-apple-ios/release/libmls_rs_uniffi_ios.a -headers ./bindings \
 	-output "buildIos/MLSrs.xcframework" 

```

And compute the checksum:
```
swift package compute-checksum MLSrs.xcframework.zip
```