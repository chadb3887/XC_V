<?php

class BouquetRepository {
	public static function getAll($db, $rGetCacheCallback, $rSetCacheCallback, $rForce = false) {
		if (!$rForce && is_callable($rGetCacheCallback)) {
			$rCache = call_user_func($rGetCacheCallback, 'bouquets', 60);
			if (!empty($rCache)) {
				return $rCache;
			}
		}

		$rOutput = array();
		$db->query('SELECT *, IF(`bouquet_order` > 0, `bouquet_order`, 999) AS `order` FROM `bouquets` ORDER BY `order` ASC;');
		foreach ($db->get_rows(true, 'id') as $rID => $rChannels) {
			$rDecodedChannels = json_decode($rChannels['bouquet_channels'], true) ?: [];
			$rDecodedMovies   = json_decode($rChannels['bouquet_movies'], true) ?: [];
			$rDecodedRadios   = json_decode($rChannels['bouquet_radios'], true) ?: [];
			$rOutput[$rID]['streams']  = array_merge($rDecodedChannels, $rDecodedMovies, $rDecodedRadios);
			$rOutput[$rID]['series']   = json_decode($rChannels['bouquet_series'], true);
			$rOutput[$rID]['channels'] = $rDecodedChannels;
			$rOutput[$rID]['movies']   = $rDecodedMovies;
			$rOutput[$rID]['radios']   = $rDecodedRadios;
		}

		if (is_callable($rSetCacheCallback)) {
			call_user_func($rSetCacheCallback, 'bouquets', $rOutput);
		}

		return $rOutput;
	}
}
