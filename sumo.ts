// Copyright 2020-present the denosaurs team. All rights reserved. MIT license.

import { Sodium, SumoAddons } from "./sumo_types.ts";
import sodium from "./dist/browsers-sumo/sodium.js";

export default sodium as Sodium & SumoAddons;

export * from "./sumo_types.ts";
