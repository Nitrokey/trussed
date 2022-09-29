(function() {var implementors = {};
implementors["ecdsa"] = [{"text":"impl&lt;C, D&gt; <a class=\"trait\" href=\"signature/signer/trait.DigestSigner.html\" title=\"trait signature::signer::DigestSigner\">DigestSigner</a>&lt;D, <a class=\"struct\" href=\"ecdsa/struct.Signature.html\" title=\"struct ecdsa::Signature\">Signature</a>&lt;C&gt;&gt; for <a class=\"struct\" href=\"ecdsa/struct.SigningKey.html\" title=\"struct ecdsa::SigningKey\">SigningKey</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: <a class=\"trait\" href=\"ecdsa/trait.Curve.html\" title=\"trait ecdsa::Curve\">Curve</a> + <a class=\"trait\" href=\"elliptic_curve/arithmetic/trait.ProjectiveArithmetic.html\" title=\"trait elliptic_curve::arithmetic::ProjectiveArithmetic\">ProjectiveArithmetic</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;D: <a class=\"trait\" href=\"digest/fixed/trait.FixedOutput.html\" title=\"trait digest::fixed::FixedOutput\">FixedOutput</a>&lt;OutputSize = <a class=\"type\" href=\"elliptic_curve/type.FieldSize.html\" title=\"type elliptic_curve::FieldSize\">FieldSize</a>&lt;C&gt;&gt; + <a class=\"trait\" href=\"digest/trait.BlockInput.html\" title=\"trait digest::BlockInput\">BlockInput</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + <a class=\"trait\" href=\"digest/trait.Reset.html\" title=\"trait digest::Reset\">Reset</a> + <a class=\"trait\" href=\"digest/trait.Update.html\" title=\"trait digest::Update\">Update</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"elliptic_curve/scalar/type.Scalar.html\" title=\"type elliptic_curve::scalar::Scalar\">Scalar</a>&lt;C&gt;: <a class=\"trait\" href=\"ecdsa/hazmat/trait.FromDigest.html\" title=\"trait ecdsa::hazmat::FromDigest\">FromDigest</a>&lt;C&gt; + <a class=\"trait\" href=\"elliptic_curve/ops/trait.Invert.html\" title=\"trait elliptic_curve::ops::Invert\">Invert</a>&lt;Output = <a class=\"type\" href=\"elliptic_curve/scalar/type.Scalar.html\" title=\"type elliptic_curve::scalar::Scalar\">Scalar</a>&lt;C&gt;&gt; + <a class=\"trait\" href=\"ecdsa/hazmat/trait.SignPrimitive.html\" title=\"trait ecdsa::hazmat::SignPrimitive\">SignPrimitive</a>&lt;C&gt; + <a class=\"trait\" href=\"zeroize/trait.Zeroize.html\" title=\"trait zeroize::Zeroize\">Zeroize</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"ecdsa/type.SignatureSize.html\" title=\"type ecdsa::SignatureSize\">SignatureSize</a>&lt;C&gt;: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.64.0/core/primitive.u8.html\">u8</a>&gt;,&nbsp;</span>","synthetic":false,"types":["ecdsa::sign::SigningKey"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()