#![allow(clippy::transmute_ptr_to_ptr)]

use crate::{
    api::{Reply, Request},
    error::Result,
    types::ClientContext,
};

pub type Interchange<B, const N: usize> = interchange::Interchange<Request<B>, Result<Reply>, N>;
pub type Requester<'a, B> = interchange::Requester<'a, Request<B>, Result<Reply>>;
pub type Responder<'a, B> = interchange::Responder<'a, Request<B>, Result<Reply>>;

// TODO: The request pipe should block if there is an unhandled
// previous request/reply. As a side effect, the service should always
// be able to assume that the reply pipe is "ready".

// PRIOR ART:
// https://xenomai.org/documentation/xenomai-2.4/html/api/group__native__queue.html
// https://doc.micrium.com/display/osiiidoc/Using+Message+Queues

pub struct ServiceEndpoint<'a, B: 'static> {
    pub interchange: Responder<'a, B>,
    // service (trusted) has this, not client (untrusted)
    // used among other things to namespace cryptographic material
    pub client_ctx: ClientContext<B>,
}

// pub type ClientEndpoint = Requester<TrussedInterchange>;
