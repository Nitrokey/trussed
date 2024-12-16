(function() {
    var type_impls = Object.fromEntries([["trussed",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Drop-for-Requester%3C'i,+Rq,+Rp%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#416\">source</a><a href=\"#impl-Drop-for-Requester%3C'i,+Rq,+Rp%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'i, Rq, Rp&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"interchange/struct.Requester.html\" title=\"struct interchange::Requester\">Requester</a>&lt;'i, Rq, Rp&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.drop\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#417\">source</a><a href=\"#method.drop\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.83.0/core/ops/drop/trait.Drop.html#tymethod.drop\" class=\"fn\">drop</a>(&amp;mut self)</h4></section></summary><div class='docblock'>Executes the destructor for this type. <a href=\"https://doc.rust-lang.org/1.83.0/core/ops/drop/trait.Drop.html#tymethod.drop\">Read more</a></div></details></div></details>","Drop","trussed::pipe::TrussedRequester"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Requester%3C'i,+Rq,+Rp%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#424\">source</a><a href=\"#impl-Requester%3C'i,+Rq,+Rp%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'i, Rq, Rp&gt; <a class=\"struct\" href=\"interchange/struct.Requester.html\" title=\"struct interchange::Requester\">Requester</a>&lt;'i, Rq, Rp&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"method.channel\" class=\"method\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#425\">source</a><h4 class=\"code-header\">pub fn <a href=\"interchange/struct.Requester.html#tymethod.channel\" class=\"fn\">channel</a>(&amp;self) -&gt; &amp;'i <a class=\"struct\" href=\"interchange/struct.Channel.html\" title=\"struct interchange::Channel\">Channel</a>&lt;Rq, Rp&gt;</h4></section><details class=\"toggle method-toggle\" open><summary><section id=\"method.state\" class=\"method\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#466\">source</a><h4 class=\"code-header\">pub fn <a href=\"interchange/struct.Requester.html#tymethod.state\" class=\"fn\">state</a>(&amp;self) -&gt; <a class=\"enum\" href=\"interchange/enum.State.html\" title=\"enum interchange::State\">State</a></h4></section></summary><div class=\"docblock\"><p>Current state of the channel.</p>\n<p>Informational only!</p>\n<p>The responder may change this state between calls,\ninternally atomics ensure correctness.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.request\" class=\"method\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#477\">source</a><h4 class=\"code-header\">pub fn <a href=\"interchange/struct.Requester.html#tymethod.request\" class=\"fn\">request</a>(&amp;mut self, request: Rq) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.83.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"interchange/struct.Error.html\" title=\"struct interchange::Error\">Error</a>&gt;</h4></section></summary><div class=\"docblock\"><p>Send a request to the responder.</p>\n<p>If efficiency is a concern, or requests need multiple steps to\nconstruct, use <code>request_mut</code> and `send_request.</p>\n<p>If the RPC state is <code>Idle</code>, this always succeeds, else calling\nis a logic error and the request is returned.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.cancel\" class=\"method\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#499\">source</a><h4 class=\"code-header\">pub fn <a href=\"interchange/struct.Requester.html#tymethod.cancel\" class=\"fn\">cancel</a>(&amp;mut self) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.83.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/1.83.0/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;Rq&gt;, <a class=\"struct\" href=\"interchange/struct.Error.html\" title=\"struct interchange::Error\">Error</a>&gt;</h4></section></summary><div class=\"docblock\"><p>Attempt to cancel a request.</p>\n<p>If the responder has not taken the request yet, this succeeds and returns\nthe request.</p>\n<p>If the responder has taken the request (is processing), we succeed and return None.</p>\n<p>In other cases (<code>Idle</code> or <code>Reponsed</code>) there is nothing to cancel and we fail.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.response\" class=\"method\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#522\">source</a><h4 class=\"code-header\">pub fn <a href=\"interchange/struct.Requester.html#tymethod.response\" class=\"fn\">response</a>(&amp;self) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.83.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.reference.html\">&amp;Rp</a>, <a class=\"struct\" href=\"interchange/struct.Error.html\" title=\"struct interchange::Error\">Error</a>&gt;</h4></section></summary><div class=\"docblock\"><p>If there is a response waiting, obtain a reference to it</p>\n<p>This may be called multiple times.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.with_response\" class=\"method\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#533\">source</a><h4 class=\"code-header\">pub fn <a href=\"interchange/struct.Requester.html#tymethod.with_response\" class=\"fn\">with_response</a>&lt;R&gt;(&amp;self, f: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/ops/function/trait.FnOnce.html\" title=\"trait core::ops::function::FnOnce\">FnOnce</a>(<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.reference.html\">&amp;Rp</a>) -&gt; R) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.83.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;R, <a class=\"struct\" href=\"interchange/struct.Error.html\" title=\"struct interchange::Error\">Error</a>&gt;</h4></section></summary><div class=\"docblock\"><p>If there is a request waiting, perform an operation with a reference to it</p>\n<p>This may be called multiple times.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.take_response\" class=\"method\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#548\">source</a><h4 class=\"code-header\">pub fn <a href=\"interchange/struct.Requester.html#tymethod.take_response\" class=\"fn\">take_response</a>(&amp;mut self) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.83.0/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;Rp&gt;</h4></section></summary><div class=\"docblock\"><p>Look for a response.\nIf the responder has sent a response, we return it.</p>\n<p>This may be called only once as it move the state to Idle.\nIf you need copies, clone the request.</p>\n</div></details></div></details>",0,"trussed::pipe::TrussedRequester"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Requester%3C'i,+Rq,+Rp%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#557-559\">source</a><a href=\"#impl-Requester%3C'i,+Rq,+Rp%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'i, Rq, Rp&gt; <a class=\"struct\" href=\"interchange/struct.Requester.html\" title=\"struct interchange::Requester\">Requester</a>&lt;'i, Rq, Rp&gt;<div class=\"where\">where\n    Rq: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.with_request_mut\" class=\"method\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#564\">source</a><h4 class=\"code-header\">pub fn <a href=\"interchange/struct.Requester.html#tymethod.with_request_mut\" class=\"fn\">with_request_mut</a>&lt;R&gt;(\n    &amp;mut self,\n    f: impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.83.0/core/ops/function/trait.FnOnce.html\" title=\"trait core::ops::function::FnOnce\">FnOnce</a>(<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.reference.html\">&amp;mut Rq</a>) -&gt; R,\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.83.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;R, <a class=\"struct\" href=\"interchange/struct.Error.html\" title=\"struct interchange::Error\">Error</a>&gt;</h4></section></summary><div class=\"docblock\"><p>Initialize a request with its default values and mutates it with <code>f</code></p>\n<p>This is usefull to build large structures in-place</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.request_mut\" class=\"method\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#590\">source</a><h4 class=\"code-header\">pub fn <a href=\"interchange/struct.Requester.html#tymethod.request_mut\" class=\"fn\">request_mut</a>(&amp;mut self) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.83.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.reference.html\">&amp;mut Rq</a>, <a class=\"struct\" href=\"interchange/struct.Error.html\" title=\"struct interchange::Error\">Error</a>&gt;</h4></section></summary><div class=\"docblock\"><p>Initialize a request with its default values and and return a mutable reference to it</p>\n<p>This is usefull to build large structures in-place</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.send_request\" class=\"method\"><a class=\"src rightside\" href=\"src/interchange/lib.rs.html#611\">source</a><h4 class=\"code-header\">pub fn <a href=\"interchange/struct.Requester.html#tymethod.send_request\" class=\"fn\">send_request</a>(&amp;mut self) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/1.83.0/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.83.0/core/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"interchange/struct.Error.html\" title=\"struct interchange::Error\">Error</a>&gt;</h4></section></summary><div class=\"docblock\"><p>Send a request that was already placed in the channel using <code>request_mut</code> or\n<code>with_request_mut</code>.</p>\n</div></details></div></details>",0,"trussed::pipe::TrussedRequester"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[11396]}