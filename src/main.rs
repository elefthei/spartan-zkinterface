mod lib;
use lib::*;
use merlin::Transcript;
use libspartan::{SNARKGens, SNARK};
use std::env;
use std::format;
use std::fs::File;
use std::io::Read;
use std::string::String;
use serde::ser::Serialize;
use serde_json::Result;

fn main() {
    let args: Vec<String> = env::args().collect();
    let usage = format!(
        "{} [prove | verify] <circuit.zkif> <inputs.zkif> <witness.zkif>",
        args.get(0).unwrap()
    );
    let circuitfn = args.get(2).unwrap();
    let inputsfn = args.get(3).unwrap();
    let witnessfn = args.get(4).unwrap();

    let mut fh = File::open(inputsfn).unwrap();
    let mut bufh = Vec::new();
    fh.read_to_end(&mut bufh).unwrap();
    let mut fcs = File::open(circuitfn).unwrap();
    let mut bufcs = Vec::new();
    fcs.read_to_end(&mut bufcs).unwrap();
    let mut fw = File::open(witnessfn).unwrap();
    let mut bufw = Vec::new();
    fw.read_to_end(&mut bufw).unwrap();

    // Initialize R1csReader
    let reader = R1csReader::new(&mut bufh, &mut bufcs, &mut bufw);
    let r1cs = R1cs::from(reader);

    // We will encode the above constraints into three matrices, where
    // the coefficients in the matrix are in the little-endian byte order
    let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

    let inst = r1cs.instance(&mut A, &mut B, &mut C);
    let assignment_inputs = r1cs.inputs_assignment();
    let assignment_vars = r1cs.vars_assignment();

    // Check if instance is satisfiable
    let res = inst.is_sat(&assignment_vars, &assignment_inputs);
    match res {
        Ok(res) => assert!(res, "Circuit should be satisfied by assignments"),
        Err(e) => std::panic!(e)
    }

    // Crypto proof public params
    let gens = r1cs.public_params();

    // create a commitment to the R1CS instance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"snark_example");
    let proof = SNARK::prove(
        &inst,
        &decomm,
        assignment_vars,
        &assignment_inputs,
        &gens,
        &mut prover_transcript,
    );

    match args.get(1).unwrap().as_str() {
        "prove" => {
            let json = serde_json::to_string_pretty(&proof).unwrap();
            println!("{}", json)
        },
        "verify" => {
            let mut verifier_transcript = Transcript::new(b"snark_example");
            assert!(proof
                .verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens)
                .is_ok());
            println!("proof verification successful");
        }
        _ => println!("{}", usage),
    }
}
