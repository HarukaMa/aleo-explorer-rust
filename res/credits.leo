program credits.aleo {

    mapping account: address => u64;

    record credits {
        owner: address,
        microcredits: u64,
    }

    transition mint(public a1: address, public a2: u64) -> credits {
        return credits {
            owner: a1,
            microcredits: a2,
        };
    }

    transition transfer_public(public a1: address, public a2: u64) { }

    transition transfer_private(a1: credits, a2: address, a3: u64) -> (credits, credits) {
        return (a1, a1);
    }

    transition transfer_private_to_public(a1: credits, public a2: address, a3: u64) -> credits {
        return a1;
    }

    transition transfer_public_to_private(public a1: address, a2: u64) -> credits {
        return credits {
            owner: a1,
            microcredits: a2,
        };
    }

    transition join(a1: credits, a2: credits) -> credits {
        return a1;
    }

    transition split(a1: credits, a2: u64) -> (credits, credits) {
        return (a1, a1);
    }

    transition fee(a1: credits, a2: u64, a3: field) -> credits {
        return a1;
    }

}