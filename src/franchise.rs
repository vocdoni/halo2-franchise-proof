#![allow(dead_code)]

use crate::halo2::{
    circuit::{Layouter, SimpleFloorPlanner},
    pasta::Fp,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};

use crate::circuit::gadget::poseidon::{Hash, Pow5T3Chip, Pow5T3Config, StateWord, Word};
use crate::circuit::gadget::utilities::cond_swap::{
    CondSwapChip, CondSwapConfig, CondSwapInstructions,
};
use crate::circuit::gadget::utilities::{CellValue, Var};
use crate::primitives::poseidon::{ConstantLength, P128Pow5T3};

/*
                       +----------+
                       |          |
PUB_censusRoot+------->+          |(key)<-----+PRI_index
                       |          |
                       | SMT      |            +----------+
                       | Verifier |            |          |
PRI_siblings+--------->+          |(value)<----+ Poseidon +<-----+--+PRI_secretKey
                       |          |            |          |      |
                       +----------+            +----------+      |
                                                                 |
                                     +----------+                |
                      +----+         |          +<---------------+
PUB_nullifier+------->+ == +<--------+ Poseidon |<-----------+PUB_processID_0
                      +----+         |          +<-----------+PUB_processID_1
                                     +----------+
PUB_voteHash
*/

#[derive(Clone, Default)]
pub struct FranchiseCircuit<const LVL: usize> {
    pub pri_index: Option<[bool; LVL]>,
    pub pri_siblings: Option<[Fp; LVL]>,
    pub pri_secret_key: Option<Fp>,
    pub pub_processid: Option<[Fp; 2]>,
    pub pub_votehash: Option<Fp>,
}

#[derive(Clone)]
pub struct FranchiseConfig {
    hash: Pow5T3Config<Fp>,
    swap: CondSwapConfig,
    instance: Column<Instance>,
}

impl<const LVL: usize> FranchiseCircuit<LVL> {
    fn hash(
        &self,
        config: &FranchiseConfig,
        mut layouter: impl Layouter<Fp>,
        values: [CellValue<Fp>; 2],
    ) -> Result<CellValue<Fp>, Error> {
        let hash_chip = Pow5T3Chip::construct(config.hash.clone());

        let hasher: Hash<
            Fp,
            Pow5T3Chip<Fp>,
            P128Pow5T3,
            ConstantLength<2_usize>,
            3_usize,
            2_usize,
        > = Hash::init(
            hash_chip,
            layouter.namespace(|| "init"),
            ConstantLength::<2>,
        )?;

        let v0 = Word::from_inner(StateWord::new(values[0].cell(), values[0].value()));
        let v1 = Word::from_inner(StateWord::new(values[1].cell(), values[1].value()));

        let hashed = hasher.hash(layouter.namespace(|| "hash"), [v0, v1])?;

        let cell_value = CellValue::new(hashed.inner().var, hashed.inner().value);

        Ok(cell_value)
    }

    fn merkle_tree(
        &self,
        config: &FranchiseConfig,
        mut layouter: impl Layouter<Fp>,
        mut root: CellValue<Fp>,
    ) -> Result<CellValue<Fp>, Error> {
        for n in 0..LVL {
            let leaf = self.load_private_input(
                layouter.namespace(|| "load witness"),
                config.swap.b,
                self.pri_siblings.map(|v| v[n]),
            )?;

            let swap_chip = CondSwapChip::<Fp>::construct(config.swap.clone());

            let (left, right) = swap_chip.swap(
                layouter.namespace(|| "mt swap"),
                (root, leaf),
                self.pri_index.map(|v| v[n]),
            )?;

            root = self.hash(&config, layouter.namespace(|| "mt hash"), [left, right])?;
        }

        Ok(root)
    }

    fn load_private_input(
        &self,
        mut layouter: impl Layouter<Fp>,
        column: Column<Advice>,
        value: Option<Fp>,
    ) -> Result<CellValue<Fp>, Error> {
        let cell = layouter.assign_region(
            || "load private input",
            |mut region| {
                let cell = region.assign_advice(
                    || format!("load leafs"),
                    column,
                    0,
                    || value.ok_or(Error::Synthesis),
                )?;

                Ok(CellValue::new(cell, value))
            },
        )?;

        Ok(cell)
    }
}

impl<const LVL: usize> Circuit<Fp> for FranchiseCircuit<LVL> {
    type Config = FranchiseConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let partial_sbox = meta.advice_column();

        let rc_a = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];

        let rc_b = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];

        meta.enable_constant(rc_b[0]);

        let swap_advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        for s_a in swap_advices {
            meta.enable_equality(s_a.into());
        }

        let instance = meta.instance_column();
        meta.enable_equality(instance.into());

        Self::Config {
            swap: CondSwapChip::configure(meta, swap_advices),
            hash: Pow5T3Chip::configure(meta, P128Pow5T3, state, partial_sbox, rc_a, rc_b),
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let process_id_0 = self.load_private_input(
            layouter.namespace(|| "load process_id[0]"),
            config.swap.a,
            self.pub_processid.map(|v| v[0]),
        )?;

        let process_id_1 = self.load_private_input(
            layouter.namespace(|| "load process_id[1]"),
            config.swap.a,
            self.pub_processid.map(|v| v[1]),
        )?;

        let secret_key = self.load_private_input(
            layouter.namespace(|| "load secret key"),
            config.swap.a,
            self.pri_secret_key,
        )?;

        let vote_hash = self.load_private_input(
            layouter.namespace(|| "load vote hash"),
            config.swap.a,
            self.pub_votehash,
        )?;

        let public_key = self.hash(
            &config,
            layouter.namespace(|| "hash secret key"),
            [secret_key, secret_key],
        )?;

        let process_id_hash = self.hash(
            &config,
            layouter.namespace(|| "hash process_id"),
            [process_id_0, process_id_1],
        )?;

        let nullifier = self.hash(
            &config,
            layouter.namespace(|| "nullifier"),
            [secret_key, process_id_hash],
        )?;

        let root = self.merkle_tree(&config, layouter.namespace(|| "mt"), public_key)?;

        // expose census root as public_input[0]
        layouter.constrain_instance(root.cell(), config.instance, 0)?;

        // expose nullifier as public_input[1]
        layouter.constrain_instance(nullifier.cell(), config.instance, 1)?;

        // expose vote hash public_input[2]
        layouter.constrain_instance(vote_hash.cell(), config.instance, 2)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::halo2::dev::CircuitLayout;
    use crate::halo2::dev::MockProver;
    use crate::halo2::pasta::Fp;
    use plotters::prelude::*;

    use super::*;
    use crate::utils::generate_test_data;

    fn print_circuit<const LVL: usize>(circuit: FranchiseCircuit<LVL>, k: u32) {
        let root = BitMapBackend::new("circuit-layout.png", (1024, 768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Circuit Layout", ("sans-serif", 6)).unwrap();

        CircuitLayout::default()
            .render(k as usize, &circuit, &root)
            .unwrap();
    }

    fn mock_test<const LVL: usize>(k: u32) {
        let (circuit, mut public) = generate_test_data::<LVL>();

        let prover = MockProver::run(k, &circuit, vec![public.clone()]).expect("cannot run mock");
        assert_eq!(Ok(()), prover.verify());

        for n in 0..public.len() {
            public[n] += Fp::from(1);
            assert!(MockProver::run(k, &circuit, vec![public.clone()])
                .expect("cannot run mock")
                .verify()
                .is_err());
            public[n] -= Fp::from(1);
        }
    }

    #[test]
    fn test_franchise() {
        mock_test::<3>(8);
    }
}
