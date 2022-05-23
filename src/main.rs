#![feature(map_try_insert)]

use std::env;
use std::fs::{File, create_dir_all};
use std::io::{Read,Write};
use std::ffi::CString;
use std::time;
use std::os::unix::fs::FileExt;
use std::os::unix::io::IntoRawFd;

use rand::{Rng, SeedableRng};
//use rand::rngs::SmallRng;
use rand::rngs::SmallRng;

use nix::unistd::{fork, execvp, ForkResult, dup2};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::signal::Signal;

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


//no inlining so that profiling properly reports the functions
#[inline(never)]
fn fuzz(data: &mut Vec<u8>) {
	let prog_name = CString::new("exif").unwrap();
	let mut mutated_jpg = File::create("mutated.jpg").unwrap();
	let arg = CString::new("mutated.jpg").unwrap();

	for i in 0..10000 {
		/*
		if i % 2 == 0 {
			flip_bits(&mut to_mutate);
		}
		else {
			magic(&mut to_mutate);
		}
		*/
		//have to reverse the vector of original bytes
		//the byte replaced by random values are randomly chosen. So imagine the case where the same byte is chosen twice
		//in the original vector, the first entry will have the valid byte for that index, and the second entry will be some dangerous junk
		//could check each index is unique in flip_bits, but that seems slow
		//so instead, here we reverse the vector. Such that any duplicate bytes, the 'correct' byte is the one that is fixed last.
		let altered_bytes : Vec<(usize, u8)> = flip_bits(data).into_iter().rev().collect();
		
		mutated_jpg.write_at(data, 0).unwrap();

		match unsafe{fork()} {
			
			Ok(ForkResult::Child) => {
				let null_fd = File::open("/dev/null").unwrap().into_raw_fd();

				//we dont want stdout/stderr, so redirect them to /dev/null
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

		//restoring the file to its original state	
		for (idx, byte) in altered_bytes {
			data[idx] = byte;
		}
	}
}


//flips a random bit in a random byte in the data
#[inline(never)]
fn flip_bits(data: &mut [u8]) -> Vec<(usize, u8)> {
	let num_flips : usize = (((data.len() -4) as f64) * 0.01).floor() as usize;
	let mut idxs : Vec<usize> =  Vec::with_capacity( num_flips);
	let mut rng = SmallRng::from_entropy();
	
	//the original unaltered bytes. This way we dont need to clone the data each time, and can instead just recover the data
	let mut  original_bytes = Vec::with_capacity(num_flips);

	//get indexes to be flipped
	for _ in 0..num_flips {
		idxs.push(rng.gen_range(4..(data.len()-4)));
	}

	for i in 0..num_flips {
		original_bytes.push((idxs[i], data[idxs[i]]));
		data[idxs[i]] = rng.gen::<u8>();
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
