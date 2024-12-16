(function() {
    var type_impls = Object.fromEntries([["trussed",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-InterchangeRef%3C'alloc,+Rq,+Rp%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#938\">source</a><a href=\"#impl-InterchangeRef%3C'alloc,+Rq,+Rp%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'alloc, Rq, Rp&gt; <a class=\"struct\" href=\"interchange/struct.InterchangeRef.html\" title=\"struct interchange::InterchangeRef\">InterchangeRef</a>&lt;'alloc, Rq, Rp&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.claim\" class=\"method\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#940\">source</a><h4 class=\"code-header\">pub fn <a href=\"interchange/struct.InterchangeRef.html#tymethod.claim\" class=\"fn\">claim</a>(\n    &amp;self,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.83.0/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;(<a class=\"struct\" href=\"interchange/struct.Requester.html\" title=\"struct interchange::Requester\">Requester</a>&lt;'alloc, Rq, Rp&gt;, <a class=\"struct\" href=\"interchange/struct.Responder.html\" title=\"struct interchange::Responder\">Responder</a>&lt;'alloc, Rq, Rp&gt;)&gt;</h4></section></summary><div class=\"docblock\"><p>Claim one of the channels of the interchange. Returns None if called more than <code>N</code> times.</p>\n</div></details></div></details>",0,"trussed::pipe::TrussedInterchange"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[1537]}