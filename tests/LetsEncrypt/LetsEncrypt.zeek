# @TEST-EXEC: zeek -C -r $TRACES/LetsEncrypt.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

