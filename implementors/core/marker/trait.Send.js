(function() {var implementors = {};
implementors["trussed"] = [{"text":"impl Send for Request","synthetic":true,"types":[]},{"text":"impl Send for Reply","synthetic":true,"types":[]},{"text":"impl Send for Agree","synthetic":true,"types":[]},{"text":"impl Send for CreateObject","synthetic":true,"types":[]},{"text":"impl Send for DebugDumpStore","synthetic":true,"types":[]},{"text":"impl Send for Decrypt","synthetic":true,"types":[]},{"text":"impl Send for Delete","synthetic":true,"types":[]},{"text":"impl Send for DeriveKey","synthetic":true,"types":[]},{"text":"impl Send for DeserializeKey","synthetic":true,"types":[]},{"text":"impl Send for Encrypt","synthetic":true,"types":[]},{"text":"impl Send for Exists","synthetic":true,"types":[]},{"text":"impl Send for FindObjects","synthetic":true,"types":[]},{"text":"impl Send for GenerateKey","synthetic":true,"types":[]},{"text":"impl Send for Hash","synthetic":true,"types":[]},{"text":"impl Send for LocateFile","synthetic":true,"types":[]},{"text":"impl Send for ReadDirFilesFirst","synthetic":true,"types":[]},{"text":"impl Send for ReadDirFilesNext","synthetic":true,"types":[]},{"text":"impl Send for ReadDirFirst","synthetic":true,"types":[]},{"text":"impl Send for ReadDirNext","synthetic":true,"types":[]},{"text":"impl Send for ReadFile","synthetic":true,"types":[]},{"text":"impl Send for RemoveFile","synthetic":true,"types":[]},{"text":"impl Send for RemoveDir","synthetic":true,"types":[]},{"text":"impl Send for RandomByteBuf","synthetic":true,"types":[]},{"text":"impl Send for SerializeKey","synthetic":true,"types":[]},{"text":"impl Send for Sign","synthetic":true,"types":[]},{"text":"impl Send for WriteFile","synthetic":true,"types":[]},{"text":"impl Send for UnsafeInjectKey","synthetic":true,"types":[]},{"text":"impl Send for UnwrapKey","synthetic":true,"types":[]},{"text":"impl Send for Verify","synthetic":true,"types":[]},{"text":"impl Send for WrapKey","synthetic":true,"types":[]},{"text":"impl Send for RequestUserConsent","synthetic":true,"types":[]},{"text":"impl Send for Reboot","synthetic":true,"types":[]},{"text":"impl Send for Agree","synthetic":true,"types":[]},{"text":"impl Send for CreateObject","synthetic":true,"types":[]},{"text":"impl Send for FindObjects","synthetic":true,"types":[]},{"text":"impl Send for DebugDumpStore","synthetic":true,"types":[]},{"text":"impl Send for Decrypt","synthetic":true,"types":[]},{"text":"impl Send for Delete","synthetic":true,"types":[]},{"text":"impl Send for DeriveKey","synthetic":true,"types":[]},{"text":"impl Send for DeserializeKey","synthetic":true,"types":[]},{"text":"impl Send for Encrypt","synthetic":true,"types":[]},{"text":"impl Send for Exists","synthetic":true,"types":[]},{"text":"impl Send for GenerateKey","synthetic":true,"types":[]},{"text":"impl Send for Hash","synthetic":true,"types":[]},{"text":"impl Send for LocateFile","synthetic":true,"types":[]},{"text":"impl Send for ReadDirFilesFirst","synthetic":true,"types":[]},{"text":"impl Send for ReadDirFilesNext","synthetic":true,"types":[]},{"text":"impl Send for ReadDirFirst","synthetic":true,"types":[]},{"text":"impl Send for ReadDirNext","synthetic":true,"types":[]},{"text":"impl Send for ReadFile","synthetic":true,"types":[]},{"text":"impl Send for RemoveDir","synthetic":true,"types":[]},{"text":"impl Send for RemoveFile","synthetic":true,"types":[]},{"text":"impl Send for RandomByteBuf","synthetic":true,"types":[]},{"text":"impl Send for SerializeKey","synthetic":true,"types":[]},{"text":"impl Send for Sign","synthetic":true,"types":[]},{"text":"impl Send for WriteFile","synthetic":true,"types":[]},{"text":"impl Send for Verify","synthetic":true,"types":[]},{"text":"impl Send for UnsafeInjectKey","synthetic":true,"types":[]},{"text":"impl Send for UnwrapKey","synthetic":true,"types":[]},{"text":"impl Send for WrapKey","synthetic":true,"types":[]},{"text":"impl Send for RequestUserConsent","synthetic":true,"types":[]},{"text":"impl Send for Reboot","synthetic":true,"types":[]},{"text":"impl&lt;'c, T, C:&nbsp;?Sized&gt; Send for FutureResult&lt;'c, T, C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: Send,<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;S&gt; Send for ClientImplementation&lt;S&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;S: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Send for ClientError","synthetic":true,"types":[]},{"text":"impl Send for Error","synthetic":true,"types":[]},{"text":"impl Send for Aes256Cbc","synthetic":true,"types":[]},{"text":"impl Send for Chacha8Poly1305","synthetic":true,"types":[]},{"text":"impl Send for Ed255","synthetic":true,"types":[]},{"text":"impl Send for X255","synthetic":true,"types":[]},{"text":"impl Send for HmacSha256","synthetic":true,"types":[]},{"text":"impl Send for P256","synthetic":true,"types":[]},{"text":"impl Send for P256Prehashed","synthetic":true,"types":[]},{"text":"impl Send for Sha256","synthetic":true,"types":[]},{"text":"impl Send for Totp","synthetic":true,"types":[]},{"text":"impl Send for Tdes","synthetic":true,"types":[]},{"text":"impl Send for Trng","synthetic":true,"types":[]},{"text":"impl Send for ServiceEndpoint","synthetic":true,"types":[]},{"text":"impl Send for TrussedInterchange","synthetic":true,"types":[]},{"text":"impl&lt;P&gt; Send for ServiceResources&lt;P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;S&gt; !Send for Fs&lt;S&gt;","synthetic":true,"types":[]},{"text":"impl Send for SerializedKey","synthetic":true,"types":[]},{"text":"impl Send for AeadUniqueId","synthetic":true,"types":[]},{"text":"impl Send for DataAttributes","synthetic":true,"types":[]},{"text":"impl Send for KeyAttributes","synthetic":true,"types":[]},{"text":"impl Send for Letters","synthetic":true,"types":[]},{"text":"impl Send for ObjectHandle","synthetic":true,"types":[]},{"text":"impl Send for PublicKeyAttributes","synthetic":true,"types":[]},{"text":"impl Send for PrivateKeyAttributes","synthetic":true,"types":[]},{"text":"impl Send for StorageAttributes","synthetic":true,"types":[]},{"text":"impl Send for UniqueId","synthetic":true,"types":[]},{"text":"impl Send for Attributes","synthetic":true,"types":[]},{"text":"impl Send for CertificateType","synthetic":true,"types":[]},{"text":"impl Send for KeyKind","synthetic":true,"types":[]},{"text":"impl Send for KeyType","synthetic":true,"types":[]},{"text":"impl Send for ObjectType","synthetic":true,"types":[]},{"text":"impl Send for StorageLocation","synthetic":true,"types":[]},{"text":"impl Send for Mechanism","synthetic":true,"types":[]},{"text":"impl Send for KeySerialization","synthetic":true,"types":[]},{"text":"impl Send for SignatureSerialization","synthetic":true,"types":[]},{"text":"impl Send for Status","synthetic":true,"types":[]},{"text":"impl Send for To","synthetic":true,"types":[]},{"text":"impl Send for Level","synthetic":true,"types":[]},{"text":"impl Send for Urgency","synthetic":true,"types":[]},{"text":"impl Send for Error","synthetic":true,"types":[]},{"text":"impl&lt;P:&nbsp;Platform&gt; Send for Service&lt;P&gt;","synthetic":false,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()