static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    sealevel::v1::PdaInput>
    fix_pda_input = {[](sealevel::v1::PdaInput *message, unsigned int seed) {
      fixup_address(message->mutable_base());
      if (message->seed().size() > 32)
        message->mutable_seed()->resize(32);
      fixup_address(message->mutable_owner());
    }};

static std::array<uint8_t, 32> create_pda(sealevel::v1::PdaInput const &pda) {
  std::array<uint8_t, 32> hash;
  std::vector<uint8_t> preimage;
  preimage.reserve(96);
  preimage.insert(preimage.end(), pda.base().begin(), pda.base().end());
  preimage.insert(preimage.end(), pda.seed().begin(), pda.seed().end());
  preimage.insert(preimage.end(), pda.owner().begin(), pda.owner().end());
  SHA256(preimage.data(), preimage.size(), hash.data());
  return hash;
}

static protobuf_mutator::libfuzzer::PostProcessorRegistration<
    sealevel::v1::AcctState>
    fix_pda_address = {[](sealevel::v1::AcctState *message, unsigned int seed) {
      if (message->has_pda()) {
        auto hash = create_pda(message->pda());
        message->set_address(hash.data(), hash.size());
      }
    }};