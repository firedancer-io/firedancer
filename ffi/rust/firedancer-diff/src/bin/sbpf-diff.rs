use firedancer_diff::{
    load_program_firedancer,
    load_program_labs,
};

fn main() {
    let elf_bytes = std::fs::read(std::env::args().nth(1).expect("Usage: sbpf-diff <prog>"))
        .expect("read failed");

    let prog_sl_res = load_program_labs(&elf_bytes);
    let prog_fd_res = load_program_firedancer(elf_bytes);

    let (prog_sl, prog_fd) = match (prog_sl_res, prog_fd_res) {
        (Err(_), Err(_)) => return,
        (Ok(_), Err(prog_fd_err)) => {
            println!("SL loaded, FD didn't ({})", prog_fd_err);
            std::process::exit(1);
        }
        (Err(prog_sl_err), Ok(_)) => {
            println!("FD loaded, SL didn't ({})", prog_sl_err);
            std::process::exit(1);
        }
        (Ok(sl), Ok(fd)) => (format!("{:?}", sl), format!("{:?}", fd)),
    };

    let mut all_matches = true;
    let mut matches = true;
    for diff in diff::lines(&prog_sl, &prog_fd) {
        let prev_matches = matches;
        matches = false;
        match diff {
            diff::Result::Left(l) => println!("SL {}", l),
            diff::Result::Both(_, _) => matches = true,
            diff::Result::Right(r) => println!("FD {}", r),
        }
        all_matches &= matches;
        if !prev_matches && matches {
            println!("...");
        }
    }

    if !all_matches {
        std::process::exit(1);
    }
}
