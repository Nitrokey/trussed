(function() {var implementors = {};
implementors["embedded_hal"] = [{"text":"impl&lt;Word, Error&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.63.0/core/fmt/trait.Write.html\" title=\"trait core::fmt::Write\">Write</a> for dyn <a class=\"trait\" href=\"embedded_hal/serial/trait.Write.html\" title=\"trait embedded_hal::serial::Write\">Write</a>&lt;Word, Error = Error&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Word: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.63.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.63.0/core/primitive.u8.html\">u8</a>&gt;,&nbsp;</span>","synthetic":false,"types":[]}];
implementors["heapless"] = [{"text":"impl&lt;const N:&nbsp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.63.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.63.0/core/fmt/trait.Write.html\" title=\"trait core::fmt::Write\">Write</a> for <a class=\"struct\" href=\"heapless/struct.String.html\" title=\"struct heapless::String\">String</a>&lt;N&gt;","synthetic":false,"types":["heapless::string::String"]},{"text":"impl&lt;const N:&nbsp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.63.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.63.0/core/fmt/trait.Write.html\" title=\"trait core::fmt::Write\">Write</a> for <a class=\"struct\" href=\"heapless/struct.Vec.html\" title=\"struct heapless::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.63.0/core/primitive.u8.html\">u8</a>, N&gt;","synthetic":false,"types":["heapless::vec::Vec"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()