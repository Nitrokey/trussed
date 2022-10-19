(function() {var implementors = {};
implementors["crypto_bigint"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/fmt/trait.UpperHex.html\" title=\"trait core::fmt::UpperHex\">UpperHex</a> for <a class=\"struct\" href=\"crypto_bigint/limb/struct.Limb.html\" title=\"struct crypto_bigint::limb::Limb\">Limb</a>","synthetic":false,"types":["crypto_bigint::limb::Limb"]},{"text":"impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/fmt/trait.UpperHex.html\" title=\"trait core::fmt::UpperHex\">UpperHex</a> for <a class=\"struct\" href=\"crypto_bigint/struct.NonZero.html\" title=\"struct crypto_bigint::NonZero\">NonZero</a>&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: <a class=\"trait\" href=\"crypto_bigint/trait.Integer.html\" title=\"trait crypto_bigint::Integer\">Integer</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/fmt/trait.UpperHex.html\" title=\"trait core::fmt::UpperHex\">UpperHex</a>,&nbsp;</span>","synthetic":false,"types":["crypto_bigint::non_zero::NonZero"]},{"text":"impl&lt;const LIMBS:&nbsp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.64.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/fmt/trait.UpperHex.html\" title=\"trait core::fmt::UpperHex\">UpperHex</a> for <a class=\"struct\" href=\"crypto_bigint/struct.UInt.html\" title=\"struct crypto_bigint::UInt\">UInt</a>&lt;LIMBS&gt;","synthetic":false,"types":["crypto_bigint::uint::UInt"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/fmt/trait.UpperHex.html\" title=\"trait core::fmt::UpperHex\">UpperHex</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/fmt/trait.UpperHex.html\" title=\"trait core::fmt::UpperHex\">UpperHex</a> for <a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;T&gt;","synthetic":false,"types":["crypto_bigint::wrapping::Wrapping"]}];
implementors["delog"] = [{"text":"impl&lt;'a, T:&nbsp;?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>, U, S&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/fmt/trait.UpperHex.html\" title=\"trait core::fmt::UpperHex\">UpperHex</a> for <a class=\"struct\" href=\"delog/hex/struct.HexStr.html\" title=\"struct delog::hex::HexStr\">HexStr</a>&lt;'a, T, U, S&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/convert/trait.AsRef.html\" title=\"trait core::convert::AsRef\">AsRef</a>&lt;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.64.0/core/primitive.u8.html\">u8</a>]&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;U: <a class=\"trait\" href=\"delog/hex/trait.Unsigned.html\" title=\"trait delog::hex::Unsigned\">Unsigned</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;S: <a class=\"trait\" href=\"delog/hex/trait.Separator.html\" title=\"trait delog::hex::Separator\">Separator</a>,&nbsp;</span>","synthetic":false,"types":["delog::hex::HexStr"]}];
implementors["ed25519"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/fmt/trait.UpperHex.html\" title=\"trait core::fmt::UpperHex\">UpperHex</a> for <a class=\"struct\" href=\"ed25519/struct.Signature.html\" title=\"struct ed25519::Signature\">Signature</a>","synthetic":false,"types":["ed25519::Signature"]}];
implementors["generic_array"] = [{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.64.0/core/primitive.u8.html\">u8</a>&gt;&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/fmt/trait.UpperHex.html\" title=\"trait core::fmt::UpperHex\">UpperHex</a> for <a class=\"struct\" href=\"generic_array/struct.GenericArray.html\" title=\"struct generic_array::GenericArray\">GenericArray</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.64.0/core/primitive.u8.html\">u8</a>, T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;T&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;T as <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/ops/arith/trait.Add.html\" title=\"trait core::ops::arith::Add\">Add</a>&lt;T&gt;&gt;::<a class=\"associatedtype\" href=\"https://doc.rust-lang.org/1.64.0/core/ops/arith/trait.Add.html#associatedtype.Output\" title=\"type core::ops::arith::Add::Output\">Output</a>: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.64.0/core/primitive.u8.html\">u8</a>&gt;,&nbsp;</span>","synthetic":false,"types":["generic_array::GenericArray"]}];
implementors["half"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/fmt/trait.UpperHex.html\" title=\"trait core::fmt::UpperHex\">UpperHex</a> for <a class=\"struct\" href=\"half/struct.bf16.html\" title=\"struct half::bf16\">bf16</a>","synthetic":false,"types":["half::bfloat::bf16"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/fmt/trait.UpperHex.html\" title=\"trait core::fmt::UpperHex\">UpperHex</a> for <a class=\"struct\" href=\"half/struct.f16.html\" title=\"struct half::f16\">f16</a>","synthetic":false,"types":["half::binary16::f16"]}];
implementors["trussed"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.64.0/core/fmt/trait.UpperHex.html\" title=\"trait core::fmt::UpperHex\">UpperHex</a> for <a class=\"struct\" href=\"trussed/key/struct.Flags.html\" title=\"struct trussed::key::Flags\">Flags</a>","synthetic":false,"types":["trussed::key::Flags"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()