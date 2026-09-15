//! Built-in APT group catalog (MITRE ATT&CK group IDs, aliases, and
//! associated malware families). Selecting a group expands into all of its
//! search terms, which the CompiledFilter matches against rule content.
//!
//! Static so the picker works offline; extend freely.

pub struct AptGroup {
    /// MITRE ATT&CK group id, e.g. "G0007"
    pub mitre_id: &'static str,
    /// Primary name shown in the UI
    pub name: &'static str,
    /// Aliases (also matched)
    pub aliases: &'static [&'static str],
    /// Malware / tool families attributed to the group (also matched)
    pub software: &'static [&'static str],
    /// Sponsor / region tag shown in UI to help picking
    pub origin: &'static str,
}

impl AptGroup {
    /// All search terms this group expands to.
    pub fn terms(&self) -> Vec<String> {
        let mut t: Vec<String> = Vec::new();
        t.push(self.name.to_string());
        t.extend(self.aliases.iter().map(|s| s.to_string()));
        t.extend(self.software.iter().map(|s| s.to_string()));
        t
    }

    /// Does a search string match this group's name/aliases/id?
    pub fn matches_search(&self, needle_lower: &str) -> bool {
        if needle_lower.is_empty() {
            return true;
        }
        self.mitre_id.to_lowercase().contains(needle_lower)
            || self.name.to_lowercase().contains(needle_lower)
            || self.origin.to_lowercase().contains(needle_lower)
            || self
                .aliases
                .iter()
                .any(|a| a.to_lowercase().contains(needle_lower))
    }
}

pub static APT_GROUPS: &[AptGroup] = &[
    AptGroup {
        mitre_id: "G0007",
        name: "APT28",
        aliases: &["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM", "Forest Blizzard", "Pawn Storm", "Tsar Team"],
        software: &["X-Agent", "XAgent", "Zebrocy", "Seduploader", "JHUHUGIT", "Komplex", "LoJax", "Drovorub", "CHOPSTICK", "ADVSTORESHELL"],
        origin: "Russia (GRU)",
    },
    AptGroup {
        mitre_id: "G0016",
        name: "APT29",
        aliases: &["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard", "UNC2452", "Dark Halo", "StellarParticle"],
        software: &["SUNBURST", "TEARDROP", "MiniDuke", "CozyDuke", "SeaDuke", "WellMess", "WellMail", "GoldMax", "EnvyScout", "BoomBox", "FoggyWeb", "MagicWeb"],
        origin: "Russia (SVR)",
    },
    AptGroup {
        mitre_id: "G0034",
        name: "Sandworm",
        aliases: &["Sandworm Team", "Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "Telebots", "ELECTRUM", "BlackEnergy Group"],
        software: &["BlackEnergy", "Industroyer", "NotPetya", "Olympic Destroyer", "Exaramel", "CaddyWiper", "HermeticWiper", "Cyclops Blink", "KillDisk"],
        origin: "Russia (GRU)",
    },
    AptGroup {
        mitre_id: "G0010",
        name: "Turla",
        aliases: &["Snake", "Venomous Bear", "Waterbug", "Uroburos", "Secret Blizzard", "Krypton"],
        software: &["Uroburos", "Carbon", "Kazuar", "Mosquito", "LightNeuron", "Crutch", "TinyTurla", "ComRAT", "Epic", "Gazer"],
        origin: "Russia (FSB)",
    },
    AptGroup {
        mitre_id: "G0032",
        name: "Lazarus Group",
        aliases: &["Lazarus", "HIDDEN COBRA", "Diamond Sleet", "ZINC", "Labyrinth Chollima", "APT38", "BlueNoroff", "Guardians of Peace"],
        software: &["WannaCry", "AppleJeus", "HOPLIGHT", "ELECTRICFISH", "BADCALL", "Manuscrypt", "Destover", "Volgmer", "FALLCHILL", "RATANKBA", "Bankshot", "DTrack", "BLINDINGCAN"],
        origin: "North Korea (RGB)",
    },
    AptGroup {
        mitre_id: "G0059",
        name: "Kimsuky",
        aliases: &["Velvet Chollima", "Thallium", "Emerald Sleet", "Black Banshee", "APT43"],
        software: &["BabyShark", "AppleSeed", "FlowerPower", "Gold Dragon", "KGH_SPY", "QuasarRAT"],
        origin: "North Korea",
    },
    AptGroup {
        mitre_id: "G0067",
        name: "APT37",
        aliases: &["Reaper", "ScarCruft", "Ricochet Chollima", "Group123", "InkySquid"],
        software: &["ROKRAT", "BLUELIGHT", "DOGCALL", "KARAE", "POORAIM", "Final1stspy"],
        origin: "North Korea",
    },
    AptGroup {
        mitre_id: "G0004",
        name: "APT41",
        aliases: &["Wicked Panda", "BARIUM", "Winnti", "Brass Typhoon", "Double Dragon"],
        software: &["ShadowPad", "Winnti Malware", "PlugX", "Cobalt Strike", "POISONPLUG", "HIGHNOON", "Crosswalk", "Speculoos", "KEYPLUG"],
        origin: "China (MSS-linked)",
    },
    AptGroup {
        mitre_id: "G0022",
        name: "APT3",
        aliases: &["Gothic Panda", "Buckeye", "UPS Team", "TG-0110"],
        software: &["Pirpi", "PlugX", "OSInfo", "shareip"],
        origin: "China (MSS)",
    },
    AptGroup {
        mitre_id: "G0045",
        name: "menuPass",
        aliases: &["APT10", "Stone Panda", "Red Apollo", "CVNX", "Potassium", "Cicada"],
        software: &["ChChes", "RedLeaves", "UPPERCUT", "Quasar", "SNUGRIDE", "NOTROBIN"],
        origin: "China (MSS)",
    },
    AptGroup {
        mitre_id: "G0096",
        name: "APT40",
        aliases: &["Leviathan", "TEMP.Periscope", "Kryptonite Panda", "Gingham Typhoon", "Mudcarp"],
        software: &["NanHaiShu", "AIRBREAK", "BADFLICK", "PHOTO", "MURKYTOP", "Derusbi"],
        origin: "China (MSS Hainan)",
    },
    AptGroup {
        mitre_id: "G0143",
        name: "Volt Typhoon",
        aliases: &["BRONZE SILHOUETTE", "Vanguard Panda", "Insidious Taurus"],
        software: &["Earthworm", "Fast Reverse Proxy", "Impacket"],
        origin: "China (state-sponsored, US CI pre-positioning)",
    },
    AptGroup {
        mitre_id: "G1045",
        name: "Salt Typhoon",
        aliases: &["GhostEmperor", "FamousSparrow", "Earth Estries", "UNC2286"],
        software: &["Demodex", "SparrowDoor", "GHOSTSPIDER", "SnappyBee"],
        origin: "China (telecom targeting)",
    },
    AptGroup {
        mitre_id: "G0027",
        name: "Threat Group-3390",
        aliases: &["APT27", "Emissary Panda", "LuckyMouse", "Iron Tiger", "Bronze Union"],
        software: &["HyperBro", "SysUpdate", "PlugX", "China Chopper", "HTTPBrowser", "OwaAuth"],
        origin: "China",
    },
    AptGroup {
        mitre_id: "G0129",
        name: "Mustang Panda",
        aliases: &["TA416", "RedDelta", "Bronze President", "Stately Taurus", "Camaro Dragon"],
        software: &["PlugX", "Korplug", "PUBLOAD", "TONESHELL", "Hodur"],
        origin: "China",
    },
    AptGroup {
        mitre_id: "G0125",
        name: "HAFNIUM",
        aliases: &["Silk Typhoon"],
        software: &["China Chopper", "ASPXSpy", "Tarrask", "ProxyLogon exploit"],
        origin: "China (MSS)",
    },
    AptGroup {
        mitre_id: "G0049",
        name: "OilRig",
        aliases: &["APT34", "Helix Kitten", "Hazel Sandstorm", "EUROPIUM", "Cobalt Gypsy"],
        software: &["QUADAGENT", "OopsIE", "SideTwist", "Saitama", "Karkoff", "DNSpionage", "RGDoor", "Helminth"],
        origin: "Iran (MOIS)",
    },
    AptGroup {
        mitre_id: "G0064",
        name: "MuddyWater",
        aliases: &["Mango Sandstorm", "MERCURY", "Static Kitten", "Seedworm", "TEMP.Zagros"],
        software: &["POWERSTATS", "PowGoop", "Small Sieve", "Canopy", "Mori", "MuddyC3"],
        origin: "Iran (MOIS)",
    },
    AptGroup {
        mitre_id: "G0003",
        name: "Charming Kitten",
        aliases: &["APT35", "Phosphorus", "Mint Sandstorm", "TA453", "Magic Hound", "Newscaster"],
        software: &["PowerLess", "BellaCiao", "HYPERSCRAPE", "GhostEcho", "CharmPower"],
        origin: "Iran (IRGC)",
    },
    AptGroup {
        mitre_id: "G0082",
        name: "APT33",
        aliases: &["Elfin", "Refined Kitten", "Peach Sandstorm", "HOLMIUM"],
        software: &["SHAPESHIFT", "DROPSHOT", "TURNEDUP", "PowerTon", "Tickler"],
        origin: "Iran",
    },
    AptGroup {
        mitre_id: "G0022x",
        name: "Pioneer Kitten",
        aliases: &["Fox Kitten", "UNC757", "Parisite", "RUBIDIUM", "Lemon Sandstorm"],
        software: &["SSHMinion", "Ngrok", "FRPC"],
        origin: "Iran (ransomware access broker)",
    },
    AptGroup {
        mitre_id: "G0037",
        name: "FIN6",
        aliases: &["Skeleton Spider", "ITG08", "Camouflage Tempest"],
        software: &["TRINITY", "FrameworkPOS", "GratefulPOS", "LockerGoga", "Ryuk", "More_eggs"],
        origin: "Criminal (payment card / ransomware)",
    },
    AptGroup {
        mitre_id: "G0046",
        name: "FIN7",
        aliases: &["Carbanak", "Carbon Spider", "Sangria Tempest", "ELBRUS", "Navigator Group"],
        software: &["Carbanak", "GRIFFON", "BOOSTWRITE", "PILLOWMINT", "Lizar", "PowerPlant", "DiceLoader"],
        origin: "Criminal (ransomware / carding)",
    },
    AptGroup {
        mitre_id: "G0092",
        name: "TA505",
        aliases: &["Hive0065", "Spandex Tempest", "CHIMBORAZO"],
        software: &["Dridex", "Locky", "FlawedAmmyy", "FlawedGrace", "SDBbot", "Get2", "Clop", "Cl0p"],
        origin: "Criminal (Clop ransomware)",
    },
    AptGroup {
        mitre_id: "G0102",
        name: "Wizard Spider",
        aliases: &["TrickBot Group", "UNC1878", "Periwinkle Tempest", "Grim Spider", "ITG23"],
        software: &["TrickBot", "Ryuk", "Conti", "BazarLoader", "BazarBackdoor", "Anchor", "Diavol", "Emotet"],
        origin: "Criminal (Conti/Ryuk)",
    },
    AptGroup {
        mitre_id: "G1015",
        name: "Scattered Spider",
        aliases: &["UNC3944", "Octo Tempest", "0ktapus", "Muddled Libra", "Starfraud"],
        software: &["ALPHV", "BlackCat", "RattyRAT", "Spectre RAT", "AveMaria", "WarZone"],
        origin: "Criminal (social engineering / ransomware)",
    },
    AptGroup {
        mitre_id: "G1024",
        name: "Akira",
        aliases: &["PUNK SPIDER", "GOLD SAHARA", "Storm-1567"],
        software: &["Akira", "Megazord", "AnyDesk", "Rclone"],
        origin: "Criminal (ransomware)",
    },
    AptGroup {
        mitre_id: "G0119",
        name: "Indrik Spider",
        aliases: &["Evil Corp", "DEV-0243", "Manatee Tempest", "GOLD DRAKE"],
        software: &["Dridex", "BitPaymer", "WastedLocker", "Hades", "Macaw", "PhorPiex", "SocGholish"],
        origin: "Criminal (Evil Corp)",
    },
    AptGroup {
        mitre_id: "G1030",
        name: "LockBit",
        aliases: &["Bitwise Spider", "GOLD MYSTIC"],
        software: &["LockBit", "LockBit Black", "StealBit", "GhostSocks"],
        origin: "Criminal (RaaS)",
    },
    AptGroup {
        mitre_id: "G0139",
        name: "Black Basta",
        aliases: &["Cardinal Spider", "Storm-1811", "UNC4393"],
        software: &["Black Basta", "QakBot", "Qbot", "SystemBC", "Brute Ratel", "DarkGate"],
        origin: "Criminal (RaaS, ex-Conti)",
    },
    AptGroup {
        mitre_id: "G0115",
        name: "GOLD SOUTHFIELD",
        aliases: &["REvil Group", "Pinchy Spider", "Sodinokibi Group"],
        software: &["REvil", "Sodinokibi", "GandCrab"],
        origin: "Criminal (RaaS)",
    },
    AptGroup {
        mitre_id: "G0008",
        name: "Carbanak Group",
        aliases: &["Anunak"],
        software: &["Carbanak", "Tinba", "Anunak"],
        origin: "Criminal (banking)",
    },
    AptGroup {
        mitre_id: "G0080",
        name: "Cobalt Group",
        aliases: &["Cobalt Gang", "GOLD KINGSWOOD", "Cobalt Spider"],
        software: &["Cobalt Strike", "More_eggs", "SpicyOmelette", "CobInt"],
        origin: "Criminal (financial)",
    },
    AptGroup {
        mitre_id: "G0094",
        name: "Kimsuky-adjacent APT-C-23",
        aliases: &["Arid Viper", "Desert Falcon", "Two-tailed Scorpion"],
        software: &["Micropsia", "GlanceLove", "FrozenCell", "AridSpy"],
        origin: "Middle East (Hamas-linked)",
    },
    AptGroup {
        mitre_id: "G0136",
        name: "APT-C-36",
        aliases: &["Blind Eagle"],
        software: &["Imminent Monitor", "AsyncRAT", "njRAT", "Remcos", "LimeRAT"],
        origin: "South America (Colombia targeting)",
    },
    AptGroup {
        mitre_id: "G0138",
        name: "Andariel",
        aliases: &["Silent Chollima", "Onyx Sleet", "PLUTONIUM", "Jumpy Pisces"],
        software: &["DTrack", "Maui", "TigerRAT", "Black RAT", "NukeSped"],
        origin: "North Korea (RGB)",
    },
    AptGroup {
        mitre_id: "G0114",
        name: "Chimera",
        aliases: &["UNC1945"],
        software: &["Cobalt Strike", "Mimikatz", "SLAPSTICK", "STEELCORGI"],
        origin: "China (airlines/semiconductor)",
    },
    AptGroup {
        mitre_id: "G0126",
        name: "SideCopy",
        aliases: &["Transparent Tribe offshoot"],
        software: &["AllaKore", "ActionRAT", "ReverseRAT", "MargulasRAT"],
        origin: "Pakistan",
    },
    AptGroup {
        mitre_id: "G0134",
        name: "Transparent Tribe",
        aliases: &["APT36", "Mythic Leopard", "ProjectM", "Earth Karkaddan"],
        software: &["Crimson", "CrimsonRAT", "ObliqueRAT", "CapraRAT", "Poseidon"],
        origin: "Pakistan",
    },
    AptGroup {
        mitre_id: "G0121",
        name: "Sidewinder",
        aliases: &["Rattlesnake", "T-APT-04", "Razor Tiger"],
        software: &["WarHawk", "SideWinder StealerBot"],
        origin: "India",
    },
];

/// Expand a set of selected group indices into the flat term list for CompiledFilter.
pub fn expand_terms(selected: &[bool]) -> Vec<String> {
    let mut terms = Vec::new();
    for (i, sel) in selected.iter().enumerate() {
        if *sel {
            if let Some(g) = APT_GROUPS.get(i) {
                terms.extend(g.terms());
            }
        }
    }
    terms.sort();
    terms.dedup();
    terms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_have_terms() {
        for g in APT_GROUPS {
            assert!(!g.terms().is_empty(), "{} has no terms", g.name);
        }
    }

    #[test]
    fn search_matches_alias() {
        let apt28 = APT_GROUPS.iter().find(|g| g.name == "APT28").unwrap();
        assert!(apt28.matches_search("fancy bear"));
        assert!(apt28.matches_search("g0007"));
        assert!(!apt28.matches_search("lazarus"));
    }

    #[test]
    fn expand_dedups() {
        let mut sel = vec![false; APT_GROUPS.len()];
        sel[0] = true;
        let terms = expand_terms(&sel);
        assert!(terms.iter().any(|t| t == "APT28"));
    }
}
