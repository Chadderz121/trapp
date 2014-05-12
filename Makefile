all:
	make -C module all
	make -C application all

clean:
	make -C module clean
	make -C application clean

insert:
	make -C module insert

remove:
	make -C module remove

insert_bad:
	make -C module insert_bad

remove_bad:
	make -C module remove_bad

run_verifier:
	make -C application run_verifier

run_prover:
	make -C application run_prover

