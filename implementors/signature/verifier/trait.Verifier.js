(function() {var implementors = {
"ecdsa":[["impl&lt;C&gt; <a class=\"trait\" href=\"signature/verifier/trait.Verifier.html\" title=\"trait signature::verifier::Verifier\">Verifier</a>&lt;<a class=\"struct\" href=\"ecdsa/struct.Signature.html\" title=\"struct ecdsa::Signature\">Signature</a>&lt;C&gt;&gt; for <a class=\"struct\" href=\"ecdsa/struct.VerifyingKey.html\" title=\"struct ecdsa::VerifyingKey\">VerifyingKey</a>&lt;C&gt;<span class=\"where fmt-newline\">where\n    C: <a class=\"trait\" href=\"ecdsa/trait.Curve.html\" title=\"trait ecdsa::Curve\">Curve</a> + <a class=\"trait\" href=\"elliptic_curve/arithmetic/trait.ProjectiveArithmetic.html\" title=\"trait elliptic_curve::arithmetic::ProjectiveArithmetic\">ProjectiveArithmetic</a> + <a class=\"trait\" href=\"ecdsa/hazmat/trait.DigestPrimitive.html\" title=\"trait ecdsa::hazmat::DigestPrimitive\">DigestPrimitive</a>,\n    C::<a class=\"associatedtype\" href=\"ecdsa/hazmat/trait.DigestPrimitive.html#associatedtype.Digest\" title=\"type ecdsa::hazmat::DigestPrimitive::Digest\">Digest</a>: <a class=\"trait\" href=\"digest/digest/trait.Digest.html\" title=\"trait digest::digest::Digest\">Digest</a>&lt;OutputSize = <a class=\"type\" href=\"elliptic_curve/type.FieldSize.html\" title=\"type elliptic_curve::FieldSize\">FieldSize</a>&lt;C&gt;&gt;,\n    <a class=\"type\" href=\"elliptic_curve/type.AffinePoint.html\" title=\"type elliptic_curve::AffinePoint\">AffinePoint</a>&lt;C&gt;: <a class=\"trait\" href=\"ecdsa/hazmat/trait.VerifyPrimitive.html\" title=\"trait ecdsa::hazmat::VerifyPrimitive\">VerifyPrimitive</a>&lt;C&gt;,\n    <a class=\"type\" href=\"elliptic_curve/scalar/type.Scalar.html\" title=\"type elliptic_curve::scalar::Scalar\">Scalar</a>&lt;C&gt;: <a class=\"trait\" href=\"ecdsa/hazmat/trait.FromDigest.html\" title=\"trait ecdsa::hazmat::FromDigest\">FromDigest</a>&lt;C&gt;,\n    <a class=\"type\" href=\"ecdsa/type.SignatureSize.html\" title=\"type ecdsa::SignatureSize\">SignatureSize</a>&lt;C&gt;: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.70.0/core/primitive.u8.html\">u8</a>&gt;,</span>"]],
"salty":[["impl <a class=\"trait\" href=\"signature/verifier/trait.Verifier.html\" title=\"trait signature::verifier::Verifier\">Verifier</a>&lt;<a class=\"struct\" href=\"ed25519/struct.Signature.html\" title=\"struct ed25519::Signature\">Signature</a>&gt; for <a class=\"struct\" href=\"salty/signature/struct.PublicKey.html\" title=\"struct salty::signature::PublicKey\">PublicKey</a>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()