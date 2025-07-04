package playReady

var Details = map[string][]app{
   "100M+ Downloads": {
      {
         playReady: "clearKey",
         title:     "Tubi: Free Movies & Live TV",
         url:       "play.google.com/store/apps/details?id=com.tubitv",
      },
      {
         playReady: "there is an error with this content",
         title:     "PlutoTV: Live TV & Free Movies",
         url:       "play.google.com/store/apps/details?id=tv.pluto.android",
      },
      {
         playReady: "sign up now",
         title:     "Max: Stream HBO, TV, & Movies",
         url:       "play.google.com/store/apps/details?id=com.wbd.stream",
      },
   },
   "50M+ Downloads": {
      {
         playReady: "there was an error loading the video",
         title:     "Plex: Stream Movies & TV",
         url:       "play.google.com/store/apps/details?id=com.plexapp.android",
      },
      {
         playReady: "sign up now",
         title:     "Hulu: Stream TV shows & movies",
         url:       "play.google.com/store/apps/details?id=com.hulu.plus",
      },
   },
   "10M+ Downloads": {
      {
         playReady: "login",
         title:     "The NBC App - Stream TV Shows",
         url:       "play.google.com/store/apps/details?id=com.nbcuni.nbc",
      },
      {
         playReady: "sign in",
         title:     "Paramount+",
         url:       "play.google.com/store/apps/details?id=com.cbs.app",
      },
      /////////////////////////////////////////////////////////////////////////////////
      {
         title:     "ITVX",
         url:       "play.google.com/store/apps/details?id=air.ITVMobilePlayer",
         playReady: "sign in",
      },
      {
         title:     "CANAL+, Live and catch-up TV",
         url:       "play.google.com/store/apps/details?id=com.canal.android.canal",
         playReady: "register",
      },
      {
         title:     "Molotov - TV en direct, replay",
         url:       "play.google.com/store/apps/details?id=tv.molotov.app",
         playReady: "available in a fee-paying option",
      },
      {
         title:     "Movistar Plus+",
         url:       "play.google.com/store/apps/details?id=es.plus.yomvi",
         playReady: "log in",
      },
   },
   "5M+ Downloads": {
      {
         playReady: "log in",
         title:     "MUBI: Curated Cinema",
         url:       "play.google.com/store/apps/details?id=com.mubi",
      },
      {
         playReady: "web client need residential proxy, license does not",
         title:     "Rakuten TV -Movies & TV Series",
         url:       "play.google.com/store/apps/details?id=tv.wuaki",
      },
   },
   "1M+ Downloads": {
      {
         playReady: "to see this content, log in",
         title:     "RTBF Auvio : direct et replay",
         url:       "play.google.com/store/apps/details?id=be.rtbf.auvio",
      },
      {
         playReady: "sign up now",
         title:     "AMC+",
         url:       "play.google.com/store/apps/details?id=com.amcplus.amcfullepisodes",
      },
      {
         playReady: "log in",
         title:     "Kanopy",
         url:       "play.google.com/store/apps/details?id=com.kanopy",
      },
      {
         playReady: "failed to load response data",
         title:     "The Roku Channel",
         url:       "play.google.com/store/apps/details?id=com.roku.web.trc",
      },
      {
         playReady: `they keep two copies of all content, so PR key is different
         from WV key`,
         title: "CTV",
         url:   "play.google.com/store/apps/details?id=ca.ctv.ctvgo",
      },
   },
   "100K+ Downloads": {
      {
         playReady: "subscribe",
         title:     "The Criterion Channel",
         url:       "play.google.com/store/apps/details?id=com.criterionchannel",
      },
   },
   "10K+ Downloads": {
      {
         playReady: "log in",
         title:     "CineMember",
         url:       "play.google.com/store/apps/details?id=nl.peoplesplayground.audienceplayer.cinemember",
      },
      {
         playReady: "join",
         title:     "Draken Film",
         url:       "play.google.com/store/apps/details?id=com.draken.android",
      },
   },
}

type app struct {
   playReady string
   title     string
   url       string
}
