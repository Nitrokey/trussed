(function() {
    var type_impls = Object.fromEntries([["littlefs2",[]],["littlefs2_core",[]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[16,22]}