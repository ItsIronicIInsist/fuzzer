#![feature(map_try_insert)]

use std::env;
use std::fs::{File, remove_file, create_dir_all};
use std::io::{Read,Write};
use std::ffi::CString;
use std::time;
use std::collections::HashMap;
use std::os::unix::fs::FileExt;
use std::os::unix::io::IntoRawFd;
use std::hash::BuildHasherDefault;

use rand::Rng;

use nix::unistd::{fork, execvp, ForkResult, dup2};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::signal::Signal;

use rustc_hash::FxHashMap;

fn main() {

	let args: Vec<String> = env::args().collect();

	if args.len() != 2 {
		println!("Invalid usage of fuzzer");
		println!("jpeg_fuzz <valid_jpg>");
		return;
	}

	let jpg_filename = &args[1];
	let mut jpg_file = match File::open(jpg_filename) {
		Ok(handle) => {
			handle
		},
		Err(err) => {
			eprintln!("Failed to open original jpg file with err {}", err);
			return;
		},
	};

	let mut data : Vec<u8> = Vec::new();
	match jpg_file.read_to_end(&mut data) {
		Ok(_) => {},
		Err(err) => {
			eprintln!("Failed to read jpg file's data. Err was {}", err);
			return;
		},
	}

	create_dir_all("./crashes").unwrap();
	let start = time::Instant::now();
	fuzz(&mut data);
	let elapsed = start.elapsed();
	eprintln!("Fuzzing 10000 iterations took {} seconds", elapsed.as_secs());

	return;
}

fn fuzz(data: &mut Vec<u8>) {
	let prog_name = CString::new("exif").unwrap();
	let mut mutated_jpg = File::create("mutated.jpg").unwrap();
	let arg = CString::new("mutated.jpg").unwrap();

	for i in 0..1000 {
		/*
		if i % 2 == 0 {
			flip_bits(&mut to_mutate);
		}
		else {
			magic(&mut to_mutate);
		}
		*/
		let altered_bytes = flip_bits(data);
		
		mutated_jpg.write_at(data, 0).unwrap();

		match unsafe{fork()} {
			
			Ok(ForkResult::Child) => {
				let null_fd = File::open("/dev/null").unwrap().into_raw_fd();

				dup2(null_fd, 1);
				dup2(null_fd, 2);

				execvp(&prog_name, &[&prog_name, &arg]).unwrap();
			},

			//child is type Pid
			Ok(ForkResult::Parent {child}) => {
				//wait for fuzzee to have a state transition. Most likely it exiting - could also be by a signal
				
				let wait_event = waitpid(child, None).unwrap();
				match wait_event {
					WaitStatus::Signaled(_, sig, _)  => {
						if sig == Signal::SIGSEGV {
							let mut crash_report = File::create(format!("./crashes/crash-{}.jpg", i)).unwrap();
							crash_report.write(data);
						}
					},
					_ => {},
				};
			},

			Err(err) => {
				panic!("Failed to fork. Err is {}", err);
			},
		};

		if i % 100 == 0 {
			eprintln!("{} loops finished", i);
		}

		for (idx, byte) in altered_bytes.iter() {
			data[*idx] = *byte;
		}
	}
}


//flips a random bit in a random byte in the data
fn flip_bits(data: &mut [u8]) -> FxHashMap<usize, u8> {
	let num_flips : usize = (((data.len() -4) as f64) * 0.01).floor() as usize;
	let mut idxs : Vec<usize> =  Vec::with_capacity( num_flips);
	let mut rng = rand::thread_rng();
	//the original unaltered bytes. This way we dont need to clone the data each time, and can instead just recover the data
	
	//let mut original_bytes : HashMap<usize, u8> = HashMap::with_capacity_and_hasher(num_flips, FxHashMap::default());
	let mut original_bytes : FxHashMap<usize, u8> = FxHashMap::default();
	original_bytes.reserve(num_flips);

	//get indexes to be flipped
	for _ in 0..num_flips {
		idxs.push(rng.gen_range(4..(data.len()-4)));
	}

	for i in 0..num_flips {
	//we dont really care if try_insert returns an error
	//That occurs if by chance, we randomly select the same index twice. If we do, the second entry wouldnt have the proper original 'byte', so we ignore it
		original_bytes.try_insert(idxs[i], data[idxs[i]]);
		data[idxs[i]] ^= 1<<(rng.gen_range(0..8) as u8);
	}
	original_bytes
}

//uses 'magic' values, which typically revolve around max/min values for shorts, ints, longs
fn magic(data: &mut [u8]) {
	let num_flips : usize = (((data.len() -4) as f64) * 0.01).floor() as usize;
	let mut idxs : Vec<usize> =  Vec::with_capacity( num_flips);
	let mut rng = rand::thread_rng();

	let magic_tuples : [(usize, u64); 12] = [
		(1,0x0),
		(1,0x7f),
		(1,0xff),
		(2,0x0),
		(2,0x7fff),
		(2,0xffff),
		(4,0x0),
		(4,0x7fffffff),
		(4,0xffffffff),
		(8,0x0),
		(8,0x7fffffffffffffff),
		(8,0xffffffffffffffff)];	

	for _ in 0..num_flips {
		//-12 here because in the extremely nulikely coincidence that we select an 8-byte magic value, and the index is less than 12 bytes from end,
		//the magic EOI bytes would become mangled
		idxs.push(rng.gen_range(4..(data.len()-12)));
	}

	for i in 0..num_flips {
		//randomly selct a tuple
		//have to unpack it, as we loop for the number of bytes in given tuple
		let (num_bytes, magic) = magic_tuples[rng.gen_range(0..12)];
		for j in 0..num_bytes {
			//little bit of shenanigans
			//the index is still bsed off the random indexes we selected, not j
			//we are looping through the number of bytes in the magic value
			//so the bit shift by j must increase a byte at a time. 8 bits in a byte, thus the bitshift increments by 8
			data[idxs[i] + j] = (magic >> (j*8)) as u8;
		}
	}
	
}
