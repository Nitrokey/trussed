(function() {var implementors = {};
implementors["trussed"] = [{"text":"impl Unpin for Request","synthetic":true,"types":[]},{"text":"impl Unpin for Reply","synthetic":true,"types":[]},{"text":"impl Unpin for Agree","synthetic":true,"types":[]},{"text":"impl Unpin for CreateObject","synthetic":true,"types":[]},{"text":"impl Unpin for DebugDumpStore","synthetic":true,"types":[]},{"text":"impl Unpin for Decrypt","synthetic":true,"types":[]},{"text":"impl Unpin for Delete","synthetic":true,"types":[]},{"text":"impl Unpin for DeriveKey","synthetic":true,"types":[]},{"text":"impl Unpin for DeserializeKey","synthetic":true,"types":[]},{"text":"impl Unpin for Encrypt","synthetic":true,"types":[]},{"text":"impl Unpin for Exists","synthetic":true,"types":[]},{"text":"impl Unpin for FindObjects","synthetic":true,"types":[]},{"text":"impl Unpin for GenerateKey","synthetic":true,"types":[]},{"text":"impl Unpin for Hash","synthetic":true,"types":[]},{"text":"impl Unpin for LocateFile","synthetic":true,"types":[]},{"text":"impl Unpin for ReadDirFilesFirst","synthetic":true,"types":[]},{"text":"impl Unpin for ReadDirFilesNext","synthetic":true,"types":[]},{"text":"impl Unpin for ReadDirFirst","synthetic":true,"types":[]},{"text":"impl Unpin for ReadDirNext","synthetic":true,"types":[]},{"text":"impl Unpin for ReadFile","synthetic":true,"types":[]},{"text":"impl Unpin for RemoveFile","synthetic":true,"types":[]},{"text":"impl Unpin for RemoveDir","synthetic":true,"types":[]},{"text":"impl Unpin for RandomByteBuf","synthetic":true,"types":[]},{"text":"impl Unpin for SerializeKey","synthetic":true,"types":[]},{"text":"impl Unpin for Sign","synthetic":true,"types":[]},{"text":"impl Unpin for WriteFile","synthetic":true,"types":[]},{"text":"impl Unpin for UnsafeInjectKey","synthetic":true,"types":[]},{"text":"impl Unpin for UnwrapKey","synthetic":true,"types":[]},{"text":"impl Unpin for Verify","synthetic":true,"types":[]},{"text":"impl Unpin for WrapKey","synthetic":true,"types":[]},{"text":"impl Unpin for RequestUserConsent","synthetic":true,"types":[]},{"text":"impl Unpin for Reboot","synthetic":true,"types":[]},{"text":"impl Unpin for Agree","synthetic":true,"types":[]},{"text":"impl Unpin for CreateObject","synthetic":true,"types":[]},{"text":"impl Unpin for FindObjects","synthetic":true,"types":[]},{"text":"impl Unpin for DebugDumpStore","synthetic":true,"types":[]},{"text":"impl Unpin for Decrypt","synthetic":true,"types":[]},{"text":"impl Unpin for Delete","synthetic":true,"types":[]},{"text":"impl Unpin for DeriveKey","synthetic":true,"types":[]},{"text":"impl Unpin for DeserializeKey","synthetic":true,"types":[]},{"text":"impl Unpin for Encrypt","synthetic":true,"types":[]},{"text":"impl Unpin for Exists","synthetic":true,"types":[]},{"text":"impl Unpin for GenerateKey","synthetic":true,"types":[]},{"text":"impl Unpin for Hash","synthetic":true,"types":[]},{"text":"impl Unpin for LocateFile","synthetic":true,"types":[]},{"text":"impl Unpin for ReadDirFilesFirst","synthetic":true,"types":[]},{"text":"impl Unpin for ReadDirFilesNext","synthetic":true,"types":[]},{"text":"impl Unpin for ReadDirFirst","synthetic":true,"types":[]},{"text":"impl Unpin for ReadDirNext","synthetic":true,"types":[]},{"text":"impl Unpin for ReadFile","synthetic":true,"types":[]},{"text":"impl Unpin for RemoveDir","synthetic":true,"types":[]},{"text":"impl Unpin for RemoveFile","synthetic":true,"types":[]},{"text":"impl Unpin for RandomByteBuf","synthetic":true,"types":[]},{"text":"impl Unpin for SerializeKey","synthetic":true,"types":[]},{"text":"impl Unpin for Sign","synthetic":true,"types":[]},{"text":"impl Unpin for WriteFile","synthetic":true,"types":[]},{"text":"impl Unpin for Verify","synthetic":true,"types":[]},{"text":"impl Unpin for UnsafeInjectKey","synthetic":true,"types":[]},{"text":"impl Unpin for UnwrapKey","synthetic":true,"types":[]},{"text":"impl Unpin for WrapKey","synthetic":true,"types":[]},{"text":"impl Unpin for RequestUserConsent","synthetic":true,"types":[]},{"text":"impl Unpin for Reboot","synthetic":true,"types":[]},{"text":"impl&lt;'c, T, C:&nbsp;?Sized&gt; Unpin for FutureResult&lt;'c, T, C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;S&gt; Unpin for ClientImplementation&lt;S&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;S: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Unpin for ClientError","synthetic":true,"types":[]},{"text":"impl Unpin for Error","synthetic":true,"types":[]},{"text":"impl Unpin for Aes256Cbc","synthetic":true,"types":[]},{"text":"impl Unpin for Chacha8Poly1305","synthetic":true,"types":[]},{"text":"impl Unpin for Ed255","synthetic":true,"types":[]},{"text":"impl Unpin for X255","synthetic":true,"types":[]},{"text":"impl Unpin for HmacSha256","synthetic":true,"types":[]},{"text":"impl Unpin for P256","synthetic":true,"types":[]},{"text":"impl Unpin for P256Prehashed","synthetic":true,"types":[]},{"text":"impl Unpin for Sha256","synthetic":true,"types":[]},{"text":"impl Unpin for Totp","synthetic":true,"types":[]},{"text":"impl Unpin for Tdes","synthetic":true,"types":[]},{"text":"impl Unpin for Trng","synthetic":true,"types":[]},{"text":"impl Unpin for ServiceEndpoint","synthetic":true,"types":[]},{"text":"impl Unpin for TrussedInterchange","synthetic":true,"types":[]},{"text":"impl&lt;P&gt; Unpin for ServiceResources&lt;P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;P&gt; Unpin for Service&lt;P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;S&gt; Unpin for Fs&lt;S&gt;","synthetic":true,"types":[]},{"text":"impl Unpin for SerializedKey","synthetic":true,"types":[]},{"text":"impl Unpin for AeadUniqueId","synthetic":true,"types":[]},{"text":"impl Unpin for DataAttributes","synthetic":true,"types":[]},{"text":"impl Unpin for KeyAttributes","synthetic":true,"types":[]},{"text":"impl Unpin for Letters","synthetic":true,"types":[]},{"text":"impl Unpin for ObjectHandle","synthetic":true,"types":[]},{"text":"impl Unpin for PublicKeyAttributes","synthetic":true,"types":[]},{"text":"impl Unpin for PrivateKeyAttributes","synthetic":true,"types":[]},{"text":"impl Unpin for StorageAttributes","synthetic":true,"types":[]},{"text":"impl Unpin for UniqueId","synthetic":true,"types":[]},{"text":"impl Unpin for Attributes","synthetic":true,"types":[]},{"text":"impl Unpin for CertificateType","synthetic":true,"types":[]},{"text":"impl Unpin for KeyKind","synthetic":true,"types":[]},{"text":"impl Unpin for KeyType","synthetic":true,"types":[]},{"text":"impl Unpin for ObjectType","synthetic":true,"types":[]},{"text":"impl Unpin for StorageLocation","synthetic":true,"types":[]},{"text":"impl Unpin for Mechanism","synthetic":true,"types":[]},{"text":"impl Unpin for KeySerialization","synthetic":true,"types":[]},{"text":"impl Unpin for SignatureSerialization","synthetic":true,"types":[]},{"text":"impl Unpin for Status","synthetic":true,"types":[]},{"text":"impl Unpin for To","synthetic":true,"types":[]},{"text":"impl Unpin for Level","synthetic":true,"types":[]},{"text":"impl Unpin for Urgency","synthetic":true,"types":[]},{"text":"impl Unpin for Error","synthetic":true,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()