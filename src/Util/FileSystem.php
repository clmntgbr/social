<?php

namespace App\Util;

class FileSystem
{
    static public function delete(string $path, $name = null): void
    {
        if (self::exist($path, $name)) {
            unlink(sprintf('%s%s', $path, $name));
        }
    }

    static public function createDirectoryIfDontExist(string $path): void
    {
        if (!(self::exist($path, null))) {
            mkdir($path, 0777, true);
        }
    }

    /**
     * @return string|bool
     */
    static public function find(string $path, ?string $name)
    {
        if (!(self::exist($path, null))) {
            return false;
        }

        //FIND EXACT CORRESPONDANCE
        foreach (scandir($path) as $file) {
            if ($name == $file) {
                return sprintf("%s%s", $path, $file);
            }
        }

        //FIND REGEX CORRESPONDANCE
        foreach (scandir($path) as $file) {
            if (preg_match($name, $file)) {
                return sprintf("%s%s", $path, $file);
            }
        }

        return false;
    }

    static public function exist(string $path, $name = null): bool
    {
        if (file_exists(sprintf('%s%s', $path, $name))) {
            return true;
        }
        return false;
    }

    static public function download(string $url, string $name, string $path): void
    {
        self::createDirectoryIfDontExist($path);
        file_put_contents(sprintf('%s%s', $path, $name), fopen($url, 'r'));
    }

    /**
     * @return bool|string
     */
    static public function unzip(string $zipfile, string $extractPath)
    {
        $zip = new \ZipArchive();

        if ($zip->open($zipfile) != 'true') {
            return false;
        }

        $unzip = $zip->getNameIndex(0);

        $zip->extractTo($extractPath);
        $zip->close();

        return $unzip;
    }

    static public function getFile(string $path, $name = null)
    {
        if (self::exist($path, $name)) {
            return file_get_contents(sprintf("%s%s", $path, $name));
        }

        return false;

    }

    static function stripAccents($str) {
        $str = preg_replace("/[^a-zA-Z0-9\s]/", "", $str);
        return strtr(utf8_decode($str), utf8_decode('àáâãäçèéêëìíîïñòóôõöùúûüýÿÀÁÂÃÄÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ'), 'aaaaaceeeeiiiinooooouuuuyyAAAAACEEEEIIIINOOOOOUUUUY');
    }
}