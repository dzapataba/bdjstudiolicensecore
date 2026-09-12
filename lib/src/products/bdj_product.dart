/// Catálogo oficial de productos del ecosistema BDJ Studio.
enum BdjProduct {
  samplePad('bdj_studio_sample_pad', 'BDJ Studio Sample Pad'),
  synthPro('bdj_studio_synth_pro', 'BDJ Studio Synth Pro'),
  stemsMusic('bdj_studio_stems_music', 'BDJ Studio Stems Music'),
  waveVideo('bdj_studio_wave_video', 'BDJ Studio Wave Video'),
  voiceSpot('bdj_studio_voice_spot', 'BDJ Studio Voice Spot'),
  searchPro('bdj_studio_search_pro', 'BDJ Studio Search Pro'),
  audioAnalyzer('bdj_studio_audio_analyzer', 'BDJ Studio Audio Analyzer');

  final String code;
  final String displayName;

  const BdjProduct(this.code, this.displayName);

  static BdjProduct? fromCode(String code) {
    for (final p in values) {
      if (p.code == code) return p;
    }
    return null;
  }
}
