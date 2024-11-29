package main

import (
	"encoding/csv"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

// Global variable to hold approved users
var approvedUsers map[string]bool

func LoadApprovedUsers(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	approvedUsers = make(map[string]bool)
	for _, record := range records {
		if len(record) > 0 {
			approvedUsers[record[0]] = true
		}
	}

	log.Println("Approved users loaded successfully")
	return nil
}

func renderUnauthorizedPage(w http.ResponseWriter, message string) {
	html := `
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error Page</title>
    <link rel="icon" type="image/x-icon" href="https://w7.pngwing.com/pngs/595/505/png-transparent-computer-icons-error-closeup-miscellaneous-text-logo-thumbnail.png">
</head>
<body>
    
<div class="title">
    <style>
        @import url(https://fonts.googleapis.com/css?family=Open+Sans:400,600);
.container {
  background-color: white;
  border-radius: 4px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);
  height: 300px;
  margin: 40px auto 50px auto;
  position: relative;
  width: 450px;
}

.artboard {
  height: 100%;
  overflow: hidden;
  position: relative;
  width: 100%;
}

.deer {
  width: 50px;
  margin: 0 auto;
  position: relative;
}

.rocking {
  animation: rocking 0.4s ease-in-out infinite alternate-reverse;
  transform-origin: bottom left;
  position: relative;
  z-index: 1;
}

.head {
  position: relative;
  width: 50px;
}

.horns {
  animation: rocking 0.4s cubic-bezier(0.4, 0, 0.2, 1) infinite alternate-reverse;
  height: 55px;
  position: relative;
  top: 21px;
  width: 50px;
}

.horn {
  position: relative;
}
.horn:before {
  background-color: #91655d;
  border-radius: 7px 7px 0 0;
  content: "";
  display: block;
  height: 55px;
  position: absolute;
  width: 7px;
  z-index: 1;
}
.horn .line {
  background-color: #91655d;
  border-radius: 7px 0 0 7px;
  height: 7px;
  width: 20px;
  margin-bottom: 15px;
  position: relative;
  top: 10px;
}
.horn .line-one {
  width: 15px;
}
.horn .line-three {
  top: -22px;
  width: 17px;
}
.horn-left {
  top: -7px;
  transform: rotate(-25deg);
}
.horn-left:before {
  box-shadow: inset 2px 0 0 0 #9c7169;
}
.horn-left .line {
  box-shadow: inset 0 2px 0 0 #9c7169;
  right: 15px;
  transform: rotate(30deg);
}
.horn-left .line-one {
  right: 10px;
}
.horn-left .line-three {
  box-shadow: inset 0 -2px 0 0 #9c7169;
  right: -3px;
  transform: rotate(160deg);
}
.horn-right {
  bottom: 55px;
  left: 40px;
  transform: rotate(25deg);
}
.horn-right:before {
  box-shadow: inset -2px 0 0 0 #835f5a;
}
.horn-right .line {
  box-shadow: inset 0 2px 0 0 #835f5a;
  right: -2px;
  transform: rotate(150deg);
}
.horn-right .line-three {
  right: 13px;
  transform: rotate(20deg);
}

.ears {
  position: absolute;
  top: 70px;
}

.ear {
  background-color: #91655d;
  border-radius: 100% 50% 50% 50%;
  height: 18px;
  position: relative;
  right: 20px;
  top: 10px;
  transform: rotate(30deg);
  transform-origin: 100%;
  width: 30px;
}
.ear:before {
  background-color: #e7beb2;
  border-radius: 100% 50% 50% 50%;
  height: 9px;
  content: "";
  display: block;
  left: 5px;
  position: relative;
  top: 5px;
  width: 15px;
}
.ear-left {
  animation: ear-left 2s cubic-bezier(0.6, -0.28, 0.74, 0.05) infinite alternate-reverse;
  transform: rotate(30deg);
}
.ear-right {
  animation: ear-right 2s cubic-bezier(0.6, -0.28, 0.74, 0.05) 2s infinite alternate-reverse;
  left: 10px;
  right: 0;
  top: -8px;
  transform: rotate(160deg);
}

.eyes {
  position: absolute;
  top: 90px;
  right: -5px;
  width: 32px;
  z-index: 2;
}
.eyes .eye {
  background: linear-gradient(0deg, white 50%, #aa8275 50%);
  border-radius: 15px;
  height: 15px;
  width: 15px;
}
.eyes .eye:before {
  animation: eaves 3s infinite alternate-reverse;
  background-color: #aa8275;
  border-radius: 9px 9px 0 0;
  height: 9px;
  content: "";
  display: block;
  position: relative;
  width: 15px;
  top: -1px;
  z-index: 1;
}
.eyes .eye:after {
  animation: eyes 3s infinite alternate-reverse;
  background-color: #495169;
  border-radius: 5px;
  height: 5px;
  content: "";
  display: block;
  left: 5px;
  position: relative;
  top: -3px;
  transform: translate(3px, 2px);
  width: 5px;
}
.eyes .eye-left {
  float: left;
}
.eyes .eye-right {
  float: right;
}

.nose {
  background-color: #91655d;
  border-radius: 0 7px 15px;
  top: 47px;
  height: 18px;
  left: 40px;
  position: relative;
  width: 20px;
  z-index: 2;
}
.nose:before {
  background-color: #fb5d5d;
  border-radius: 15px;
  content: "";
  display: block;
  height: 14px;
  position: absolute;
  right: -0.5px;
  top: -0.5px;
  width: 16px;
}
.nose:after {
  background-color: white;
  border-radius: 5px;
  content: "";
  display: block;
  height: 2px;
  position: absolute;
  right: 4px;
  top: 2px;
  width: 5px;
}

.body {
  background-color: #91655d;
  border-radius: 50px 50px 0;
  box-shadow: inset 7px 0 0 0 #9c7169;
  height: 140px;
  position: relative;
  width: 50px;
  z-index: 1;
}
.body:before {
  background-color: #e7beb2;
  border-radius: 20px 0 0 20px;
  bottom: 20px;
  box-shadow: inset -7px 0 0 0 #c39e9a;
  content: "";
  display: block;
  height: 65px;
  position: absolute;
  right: 0;
  width: 20px;
}

.hooves {
  position: relative;
  bottom: 40px;
  right: 34px;
}

.hoof-one {
  animation: jump 0.3s ease-in-out infinite alternate-reverse;
  left: 10px;
  position: relative;
  top: 70px;
  transform: rotate(25deg);
  transform-origin: 100% 50%;
}
.hoof-one .line {
  height: 30px;
  border: 20px solid;
  border-radius: 40px;
  border-color: transparent transparent #91655d transparent;
  left: 25px;
  width: 30px;
  position: relative;
  top: 5px;
  transform: rotate(-30deg);
}
.hoof-one .anim-part {
  position: relative;
  bottom: 23px;
  left: 81px;
  transform: rotate(-75deg);
  transform-origin: left;
}
.hoof-one .circle {
  animation: hoof-one 0.3s ease-in-out infinite alternate-reverse;
  background-color: #91655d;
  height: 20px;
  width: 20px;
  border-radius: 30px;
  transform: translateX(3px) rotate(0deg);
}
.hoof-one .circle-last {
  border-radius: 20px 0 0 20px;
  transform: translateX(2px) rotate(0deg);
}
.hoof-one .circle-last:before {
  content: "";
  display: block;
  border-top: 20px solid #674a4a;
  border-left: 7px solid transparent;
  height: 0;
  left: 10px;
  width: 7px;
  position: relative;
  z-index: 1;
}
.hoof-one .circle-last:after {
  background-color: #ffb63c;
  border-radius: 10px;
  bottom: 30px;
  content: "";
  display: block;
  height: 40px;
  left: 19px;
  position: relative;
  width: 9px;
}
.hoof-two {
  animation: jump-two 0.3s ease-in-out infinite alternate-reverse;
  left: 55px;
  position: relative;
  top: 10px;
  z-index: -1;
}
.hoof-two .line-one, .hoof-two .line-two {
  height: 10px;
  border: 20px solid;
  border-radius: 40px;
  border-color: transparent transparent #91655d transparent;
  width: 10px;
  position: absolute;
}
.hoof-two .line-one {
  transform: rotate(-45deg);
}
.hoof-two .line-two {
  left: 30px;
  transform: rotate(135deg);
}

.tail {
  background-color: #9c7169;
  bottom: 0;
  left: 4px;
  position: absolute;
  width: 20px;
  z-index: 0;
}
.tail .circle {
  -webkit-animation: tail 2s cubic-bezier(0, 0.02, 0.9, 2) infinite;
          animation: tail 2s cubic-bezier(0, 0.02, 0.9, 2) infinite;
  background-color: #9c7169;
  border-radius: 11px;
  height: 12px;
  position: relative;
  right: 2px;
  transform: rotate(-5deg);
  width: 12px;
}

.legs {
  position: relative;
}
.legs:before {
  background: linear-gradient(to left, #91655d 50%, #9c7169 50%);
  bottom: 0;
  content: "";
  display: block;
  height: 10px;
  left: 7px;
  position: absolute;
  width: 30px;
  z-index: 0;
}

.leg-left:before, .leg-left:after, .leg-right:before, .leg-right:after {
  content: "";
  display: block;
  position: absolute;
  z-index: 1;
}
.leg-left .anim-part {
  animation: leg-left 0.4s ease-out infinite alternate-reverse;
  position: relative;
  top: 1px;
  transform: rotate(5deg) translateX(3px);
  transform-origin: right;
  z-index: 2;
}
.leg-left .anim-part:before, .leg-left .anim-part:after {
  content: "";
  display: block;
  position: absolute;
  z-index: 1;
}
.leg-left .anim-part:before {
  height: 16px;
  width: 16px;
  border: 20px solid;
  border-radius: 30px;
  border-color: transparent #835f5b transparent transparent;
  transform: rotate(-45deg);
  top: -17px;
  left: 17px;
}
.leg-left .anim-part .line {
  background-color: #835f5b;
  height: 25px;
  position: absolute;
  width: 20px;
  left: 51px;
  top: 7px;
  z-index: 2;
  transform: skew(-9deg);
}
.leg-left .anim-part:after {
  background-color: #835f5b;
  height: 20px;
  left: 33px;
  top: -20px;
  width: 24px;
}
.leg-left:after {
  background-color: #674a4a;
  height: 13px;
  left: 48px;
  top: 32px;
  transform: skew(-8deg);
  width: 20px;
  z-index: 2;
}
.leg-right {
  position: relative;
  right: 10px;
}
.leg-right:before {
  height: 30px;
  width: 38px;
  border: 20px solid;
  border-radius: 40px;
  border-color: #91655d transparent transparent transparent;
  transform: rotate(-15deg);
  z-index: 3;
  top: -29px;
  left: 21px;
}
.leg-right .anim-part {
  position: absolute;
  left: 64px;
  bottom: 9px;
  transform: rotate(43deg);
  z-index: 2;
}
.leg-right .anim-part .circle {
  animation: leg-right 0.4s ease-out infinite alternate-reverse;
  width: 20px;
  height: 20px;
  background-color: #91655d;
  border-radius: 20px;
  transform: translateX(4px) rotate(4deg);
}
.leg-right .anim-part .circle-last {
  border-radius: 20px 0 0 20px;
}
.leg-right .anim-part .circle-last:before {
  content: "";
  display: block;
  border-bottom: 20px solid #674a4a;
  border-right: 2px solid transparent;
  height: 0;
  left: 15px;
  width: 11px;
  position: relative;
  z-index: 1;
}

.presents {
  top: 3px;
  height: 45px;
  margin: 0 auto;
  position: relative;
  width: 110px;
}
.presents:after {
  animation: shadow 0.4s ease-out infinite alternate-reverse;
  background-color: #e7eff7;
  bottom: 0;
  border-radius: 7px;
  content: "";
  display: block;
  height: 7px;
  left: -22px;
  position: absolute;
  width: 170px;
}

.present {
  border-radius: 4px;
  bottom: 3px;
  position: absolute;
  z-index: 1;
}
.present:before, .present:after {
  content: "";
  display: block;
  position: relative;
}
.present:before {
  border-radius: 4px 4px 2px 2px;
  box-shadow: 0 2px 0 0 rgba(0, 0, 0, 0.04);
  right: 1px;
}
.present-one {
  background-color: #fb5d5d;
  height: 45px;
  right: 32px;
  width: 45px;
  z-index: 2;
}
.present-one:before {
  background-color: #fc7676;
  height: 12px;
  width: 47px;
}
.present-two {
  background-color: #82dfe3;
  height: 30px;
  width: 30px;
}
.present-two:before {
  background-color: #97e4e8;
  height: 10px;
  width: 32px;
}
.present-two:after {
  background-color: #69b2cb;
  bottom: 10px;
  height: 100%;
  left: 7px;
  width: 5px;
}
.present-two-right {
  right: 5px;
}
.present-three {
  background-color: #ffb63c;
  height: 25px;
  left: 25px;
  margin: auto;
  width: 25px;
  z-index: 2;
}
.present-three:before {
  background-color: #ffc056;
  height: 8px;
  width: 27px;
}
.present-three:after {
  background-color: #fb5353;
  bottom: 8px;
  height: 100%;
  left: 13px;
  width: 5px;
}

.snowflake {
  background-color: #e4e4e4;
  border-radius: 3px;
  height: 3px;
  position: absolute;
  top: 0;
  width: 3px;
  z-index: 3;
}

.snowflake:nth-child(0) {
  -webkit-animation: snow-0 11s infinite;
          animation: snow-0 11s infinite;
}

@-webkit-keyframes snow-0 {
  from {
    transform: translate(199px, -105px);
  }
  to {
    transform: translate(199px, 583px);
  }
}

@keyframes snow-0 {
  from {
    transform: translate(199px, -105px);
  }
  to {
    transform: translate(199px, 583px);
  }
}
.snowflake:nth-child(1) {
  -webkit-animation: snow-1 11s infinite;
          animation: snow-1 11s infinite;
}

@-webkit-keyframes snow-1 {
  from {
    transform: translate(248px, -85px);
  }
  to {
    transform: translate(248px, 700px);
  }
}

@keyframes snow-1 {
  from {
    transform: translate(248px, -85px);
  }
  to {
    transform: translate(248px, 700px);
  }
}
.snowflake:nth-child(2) {
  -webkit-animation: snow-2 14s infinite;
          animation: snow-2 14s infinite;
}

@-webkit-keyframes snow-2 {
  from {
    transform: translate(228px, -199px);
  }
  to {
    transform: translate(228px, 659px);
  }
}

@keyframes snow-2 {
  from {
    transform: translate(228px, -199px);
  }
  to {
    transform: translate(228px, 659px);
  }
}
.snowflake:nth-child(3) {
  -webkit-animation: snow-3 9s infinite;
          animation: snow-3 9s infinite;
}

@-webkit-keyframes snow-3 {
  from {
    transform: translate(136px, -135px);
  }
  to {
    transform: translate(136px, 650px);
  }
}

@keyframes snow-3 {
  from {
    transform: translate(136px, -135px);
  }
  to {
    transform: translate(136px, 650px);
  }
}
.snowflake:nth-child(4) {
  -webkit-animation: snow-4 12s infinite;
          animation: snow-4 12s infinite;
}

@-webkit-keyframes snow-4 {
  from {
    transform: translate(396px, -205px);
  }
  to {
    transform: translate(396px, 490px);
  }
}

@keyframes snow-4 {
  from {
    transform: translate(396px, -205px);
  }
  to {
    transform: translate(396px, 490px);
  }
}
.snowflake:nth-child(5) {
  -webkit-animation: snow-5 12s infinite;
          animation: snow-5 12s infinite;
}

@-webkit-keyframes snow-5 {
  from {
    transform: translate(313px, -268px);
  }
  to {
    transform: translate(313px, 593px);
  }
}

@keyframes snow-5 {
  from {
    transform: translate(313px, -268px);
  }
  to {
    transform: translate(313px, 593px);
  }
}
.snowflake:nth-child(6) {
  -webkit-animation: snow-6 13s infinite;
          animation: snow-6 13s infinite;
}

@-webkit-keyframes snow-6 {
  from {
    transform: translate(200px, -22px);
  }
  to {
    transform: translate(200px, 483px);
  }
}

@keyframes snow-6 {
  from {
    transform: translate(200px, -22px);
  }
  to {
    transform: translate(200px, 483px);
  }
}
.snowflake:nth-child(7) {
  -webkit-animation: snow-7 8s infinite;
          animation: snow-7 8s infinite;
}

@-webkit-keyframes snow-7 {
  from {
    transform: translate(244px, -149px);
  }
  to {
    transform: translate(244px, 520px);
  }
}

@keyframes snow-7 {
  from {
    transform: translate(244px, -149px);
  }
  to {
    transform: translate(244px, 520px);
  }
}
.snowflake:nth-child(8) {
  -webkit-animation: snow-8 9s infinite;
          animation: snow-8 9s infinite;
}

@-webkit-keyframes snow-8 {
  from {
    transform: translate(120px, -48px);
  }
  to {
    transform: translate(120px, 465px);
  }
}

@keyframes snow-8 {
  from {
    transform: translate(120px, -48px);
  }
  to {
    transform: translate(120px, 465px);
  }
}
.snowflake:nth-child(9) {
  -webkit-animation: snow-9 6s infinite;
          animation: snow-9 6s infinite;
}

@-webkit-keyframes snow-9 {
  from {
    transform: translate(87px, -219px);
  }
  to {
    transform: translate(87px, 600px);
  }
}

@keyframes snow-9 {
  from {
    transform: translate(87px, -219px);
  }
  to {
    transform: translate(87px, 600px);
  }
}
.snowflake:nth-child(10) {
  -webkit-animation: snow-10 9s infinite;
          animation: snow-10 9s infinite;
}

@-webkit-keyframes snow-10 {
  from {
    transform: translate(317px, -219px);
  }
  to {
    transform: translate(317px, 700px);
  }
}

@keyframes snow-10 {
  from {
    transform: translate(317px, -219px);
  }
  to {
    transform: translate(317px, 700px);
  }
}
.snowflake:nth-child(11) {
  -webkit-animation: snow-11 7s infinite;
          animation: snow-11 7s infinite;
}

@-webkit-keyframes snow-11 {
  from {
    transform: translate(249px, -39px);
  }
  to {
    transform: translate(249px, 529px);
  }
}

@keyframes snow-11 {
  from {
    transform: translate(249px, -39px);
  }
  to {
    transform: translate(249px, 529px);
  }
}
.snowflake:nth-child(12) {
  -webkit-animation: snow-12 13s infinite;
          animation: snow-12 13s infinite;
}

@-webkit-keyframes snow-12 {
  from {
    transform: translate(15px, -145px);
  }
  to {
    transform: translate(15px, 523px);
  }
}

@keyframes snow-12 {
  from {
    transform: translate(15px, -145px);
  }
  to {
    transform: translate(15px, 523px);
  }
}
.snowflake:nth-child(13) {
  -webkit-animation: snow-13 12s infinite;
          animation: snow-13 12s infinite;
}

@-webkit-keyframes snow-13 {
  from {
    transform: translate(158px, -76px);
  }
  to {
    transform: translate(158px, 629px);
  }
}

@keyframes snow-13 {
  from {
    transform: translate(158px, -76px);
  }
  to {
    transform: translate(158px, 629px);
  }
}
.snowflake:nth-child(14) {
  -webkit-animation: snow-14 8s infinite;
          animation: snow-14 8s infinite;
}

@-webkit-keyframes snow-14 {
  from {
    transform: translate(103px, -51px);
  }
  to {
    transform: translate(103px, 411px);
  }
}

@keyframes snow-14 {
  from {
    transform: translate(103px, -51px);
  }
  to {
    transform: translate(103px, 411px);
  }
}
.snowflake:nth-child(15) {
  -webkit-animation: snow-15 7s infinite;
          animation: snow-15 7s infinite;
}

@-webkit-keyframes snow-15 {
  from {
    transform: translate(167px, -221px);
  }
  to {
    transform: translate(167px, 471px);
  }
}

@keyframes snow-15 {
  from {
    transform: translate(167px, -221px);
  }
  to {
    transform: translate(167px, 471px);
  }
}
.snowflake:nth-child(16) {
  -webkit-animation: snow-16 7s infinite;
          animation: snow-16 7s infinite;
}

@-webkit-keyframes snow-16 {
  from {
    transform: translate(216px, 0px);
  }
  to {
    transform: translate(216px, 519px);
  }
}

@keyframes snow-16 {
  from {
    transform: translate(216px, 0px);
  }
  to {
    transform: translate(216px, 519px);
  }
}
.snowflake:nth-child(17) {
  -webkit-animation: snow-17 8s infinite;
          animation: snow-17 8s infinite;
}

@-webkit-keyframes snow-17 {
  from {
    transform: translate(341px, -4px);
  }
  to {
    transform: translate(341px, 570px);
  }
}

@keyframes snow-17 {
  from {
    transform: translate(341px, -4px);
  }
  to {
    transform: translate(341px, 570px);
  }
}
.snowflake:nth-child(18) {
  -webkit-animation: snow-18 10s infinite;
          animation: snow-18 10s infinite;
}

@-webkit-keyframes snow-18 {
  from {
    transform: translate(317px, -9px);
  }
  to {
    transform: translate(317px, 582px);
  }
}

@keyframes snow-18 {
  from {
    transform: translate(317px, -9px);
  }
  to {
    transform: translate(317px, 582px);
  }
}
.snowflake:nth-child(19) {
  -webkit-animation: snow-19 7s infinite;
          animation: snow-19 7s infinite;
}

@-webkit-keyframes snow-19 {
  from {
    transform: translate(119px, -275px);
  }
  to {
    transform: translate(119px, 649px);
  }
}

@keyframes snow-19 {
  from {
    transform: translate(119px, -275px);
  }
  to {
    transform: translate(119px, 649px);
  }
}
.snowflake:nth-child(20) {
  -webkit-animation: snow-20 15s infinite;
          animation: snow-20 15s infinite;
}

@-webkit-keyframes snow-20 {
  from {
    transform: translate(128px, -282px);
  }
  to {
    transform: translate(128px, 595px);
  }
}

@keyframes snow-20 {
  from {
    transform: translate(128px, -282px);
  }
  to {
    transform: translate(128px, 595px);
  }
}
.snowflake:nth-child(21) {
  -webkit-animation: snow-21 12s infinite;
          animation: snow-21 12s infinite;
}

@-webkit-keyframes snow-21 {
  from {
    transform: translate(253px, -188px);
  }
  to {
    transform: translate(253px, 537px);
  }
}

@keyframes snow-21 {
  from {
    transform: translate(253px, -188px);
  }
  to {
    transform: translate(253px, 537px);
  }
}
.snowflake:nth-child(22) {
  -webkit-animation: snow-22 7s infinite;
          animation: snow-22 7s infinite;
}

@-webkit-keyframes snow-22 {
  from {
    transform: translate(305px, -238px);
  }
  to {
    transform: translate(305px, 559px);
  }
}

@keyframes snow-22 {
  from {
    transform: translate(305px, -238px);
  }
  to {
    transform: translate(305px, 559px);
  }
}
.snowflake:nth-child(23) {
  -webkit-animation: snow-23 7s infinite;
          animation: snow-23 7s infinite;
}

@-webkit-keyframes snow-23 {
  from {
    transform: translate(245px, -240px);
  }
  to {
    transform: translate(245px, 589px);
  }
}

@keyframes snow-23 {
  from {
    transform: translate(245px, -240px);
  }
  to {
    transform: translate(245px, 589px);
  }
}
.snowflake:nth-child(24) {
  -webkit-animation: snow-24 9s infinite;
          animation: snow-24 9s infinite;
}

@-webkit-keyframes snow-24 {
  from {
    transform: translate(332px, -246px);
  }
  to {
    transform: translate(332px, 534px);
  }
}

@keyframes snow-24 {
  from {
    transform: translate(332px, -246px);
  }
  to {
    transform: translate(332px, 534px);
  }
}
.snowflake:nth-child(25) {
  -webkit-animation: snow-25 8s infinite;
          animation: snow-25 8s infinite;
}

@-webkit-keyframes snow-25 {
  from {
    transform: translate(369px, -22px);
  }
  to {
    transform: translate(369px, 598px);
  }
}

@keyframes snow-25 {
  from {
    transform: translate(369px, -22px);
  }
  to {
    transform: translate(369px, 598px);
  }
}
.snowflake:nth-child(26) {
  -webkit-animation: snow-26 15s infinite;
          animation: snow-26 15s infinite;
}

@-webkit-keyframes snow-26 {
  from {
    transform: translate(342px, -284px);
  }
  to {
    transform: translate(342px, 514px);
  }
}

@keyframes snow-26 {
  from {
    transform: translate(342px, -284px);
  }
  to {
    transform: translate(342px, 514px);
  }
}
.snowflake:nth-child(27) {
  -webkit-animation: snow-27 14s infinite;
          animation: snow-27 14s infinite;
}

@-webkit-keyframes snow-27 {
  from {
    transform: translate(21px, -34px);
  }
  to {
    transform: translate(21px, 445px);
  }
}

@keyframes snow-27 {
  from {
    transform: translate(21px, -34px);
  }
  to {
    transform: translate(21px, 445px);
  }
}
.snowflake:nth-child(28) {
  -webkit-animation: snow-28 11s infinite;
          animation: snow-28 11s infinite;
}

@-webkit-keyframes snow-28 {
  from {
    transform: translate(417px, -122px);
  }
  to {
    transform: translate(417px, 589px);
  }
}

@keyframes snow-28 {
  from {
    transform: translate(417px, -122px);
  }
  to {
    transform: translate(417px, 589px);
  }
}
.snowflake:nth-child(29) {
  -webkit-animation: snow-29 6s infinite;
          animation: snow-29 6s infinite;
}

@-webkit-keyframes snow-29 {
  from {
    transform: translate(125px, -216px);
  }
  to {
    transform: translate(125px, 659px);
  }
}

@keyframes snow-29 {
  from {
    transform: translate(125px, -216px);
  }
  to {
    transform: translate(125px, 659px);
  }
}
.snowflake:nth-child(30) {
  -webkit-animation: snow-30 13s infinite;
          animation: snow-30 13s infinite;
}

@-webkit-keyframes snow-30 {
  from {
    transform: translate(335px, -101px);
  }
  to {
    transform: translate(335px, 534px);
  }
}

@keyframes snow-30 {
  from {
    transform: translate(335px, -101px);
  }
  to {
    transform: translate(335px, 534px);
  }
}
.snowflake:nth-child(31) {
  -webkit-animation: snow-31 15s infinite;
          animation: snow-31 15s infinite;
}

@-webkit-keyframes snow-31 {
  from {
    transform: translate(331px, -151px);
  }
  to {
    transform: translate(331px, 467px);
  }
}

@keyframes snow-31 {
  from {
    transform: translate(331px, -151px);
  }
  to {
    transform: translate(331px, 467px);
  }
}
.snowflake:nth-child(32) {
  -webkit-animation: snow-32 12s infinite;
          animation: snow-32 12s infinite;
}

@-webkit-keyframes snow-32 {
  from {
    transform: translate(338px, -297px);
  }
  to {
    transform: translate(338px, 619px);
  }
}

@keyframes snow-32 {
  from {
    transform: translate(338px, -297px);
  }
  to {
    transform: translate(338px, 619px);
  }
}
.snowflake:nth-child(33) {
  -webkit-animation: snow-33 13s infinite;
          animation: snow-33 13s infinite;
}

@-webkit-keyframes snow-33 {
  from {
    transform: translate(85px, -4px);
  }
  to {
    transform: translate(85px, 627px);
  }
}

@keyframes snow-33 {
  from {
    transform: translate(85px, -4px);
  }
  to {
    transform: translate(85px, 627px);
  }
}
.snowflake:nth-child(34) {
  -webkit-animation: snow-34 14s infinite;
          animation: snow-34 14s infinite;
}

@-webkit-keyframes snow-34 {
  from {
    transform: translate(398px, -221px);
  }
  to {
    transform: translate(398px, 569px);
  }
}

@keyframes snow-34 {
  from {
    transform: translate(398px, -221px);
  }
  to {
    transform: translate(398px, 569px);
  }
}
.snowflake:nth-child(35) {
  -webkit-animation: snow-35 15s infinite;
          animation: snow-35 15s infinite;
}

@-webkit-keyframes snow-35 {
  from {
    transform: translate(106px, -279px);
  }
  to {
    transform: translate(106px, 675px);
  }
}

@keyframes snow-35 {
  from {
    transform: translate(106px, -279px);
  }
  to {
    transform: translate(106px, 675px);
  }
}
.snowflake:nth-child(36) {
  -webkit-animation: snow-36 12s infinite;
          animation: snow-36 12s infinite;
}

@-webkit-keyframes snow-36 {
  from {
    transform: translate(349px, -191px);
  }
  to {
    transform: translate(349px, 438px);
  }
}

@keyframes snow-36 {
  from {
    transform: translate(349px, -191px);
  }
  to {
    transform: translate(349px, 438px);
  }
}
.snowflake:nth-child(37) {
  -webkit-animation: snow-37 9s infinite;
          animation: snow-37 9s infinite;
}

@-webkit-keyframes snow-37 {
  from {
    transform: translate(437px, -41px);
  }
  to {
    transform: translate(437px, 669px);
  }
}

@keyframes snow-37 {
  from {
    transform: translate(437px, -41px);
  }
  to {
    transform: translate(437px, 669px);
  }
}
.snowflake:nth-child(38) {
  -webkit-animation: snow-38 11s infinite;
          animation: snow-38 11s infinite;
}

@-webkit-keyframes snow-38 {
  from {
    transform: translate(359px, -161px);
  }
  to {
    transform: translate(359px, 590px);
  }
}

@keyframes snow-38 {
  from {
    transform: translate(359px, -161px);
  }
  to {
    transform: translate(359px, 590px);
  }
}
.snowflake:nth-child(39) {
  -webkit-animation: snow-39 11s infinite;
          animation: snow-39 11s infinite;
}

@-webkit-keyframes snow-39 {
  from {
    transform: translate(46px, -289px);
  }
  to {
    transform: translate(46px, 413px);
  }
}

@keyframes snow-39 {
  from {
    transform: translate(46px, -289px);
  }
  to {
    transform: translate(46px, 413px);
  }
}
.snowflake:nth-child(40) {
  -webkit-animation: snow-40 13s infinite;
          animation: snow-40 13s infinite;
}

@-webkit-keyframes snow-40 {
  from {
    transform: translate(448px, -88px);
  }
  to {
    transform: translate(448px, 472px);
  }
}

@keyframes snow-40 {
  from {
    transform: translate(448px, -88px);
  }
  to {
    transform: translate(448px, 472px);
  }
}
.snowflake:nth-child(41) {
  -webkit-animation: snow-41 11s infinite;
          animation: snow-41 11s infinite;
}

@-webkit-keyframes snow-41 {
  from {
    transform: translate(112px, -266px);
  }
  to {
    transform: translate(112px, 574px);
  }
}

@keyframes snow-41 {
  from {
    transform: translate(112px, -266px);
  }
  to {
    transform: translate(112px, 574px);
  }
}
.snowflake:nth-child(42) {
  -webkit-animation: snow-42 10s infinite;
          animation: snow-42 10s infinite;
}

@-webkit-keyframes snow-42 {
  from {
    transform: translate(166px, -293px);
  }
  to {
    transform: translate(166px, 621px);
  }
}

@keyframes snow-42 {
  from {
    transform: translate(166px, -293px);
  }
  to {
    transform: translate(166px, 621px);
  }
}
.snowflake:nth-child(43) {
  -webkit-animation: snow-43 7s infinite;
          animation: snow-43 7s infinite;
}

@-webkit-keyframes snow-43 {
  from {
    transform: translate(141px, -162px);
  }
  to {
    transform: translate(141px, 630px);
  }
}

@keyframes snow-43 {
  from {
    transform: translate(141px, -162px);
  }
  to {
    transform: translate(141px, 630px);
  }
}
.snowflake:nth-child(44) {
  -webkit-animation: snow-44 10s infinite;
          animation: snow-44 10s infinite;
}

@-webkit-keyframes snow-44 {
  from {
    transform: translate(196px, -58px);
  }
  to {
    transform: translate(196px, 521px);
  }
}

@keyframes snow-44 {
  from {
    transform: translate(196px, -58px);
  }
  to {
    transform: translate(196px, 521px);
  }
}
.snowflake:nth-child(45) {
  -webkit-animation: snow-45 6s infinite;
          animation: snow-45 6s infinite;
}

@-webkit-keyframes snow-45 {
  from {
    transform: translate(396px, -113px);
  }
  to {
    transform: translate(396px, 631px);
  }
}

@keyframes snow-45 {
  from {
    transform: translate(396px, -113px);
  }
  to {
    transform: translate(396px, 631px);
  }
}
.snowflake:nth-child(46) {
  -webkit-animation: snow-46 12s infinite;
          animation: snow-46 12s infinite;
}

@-webkit-keyframes snow-46 {
  from {
    transform: translate(76px, -272px);
  }
  to {
    transform: translate(76px, 620px);
  }
}

@keyframes snow-46 {
  from {
    transform: translate(76px, -272px);
  }
  to {
    transform: translate(76px, 620px);
  }
}
.snowflake:nth-child(47) {
  -webkit-animation: snow-47 8s infinite;
          animation: snow-47 8s infinite;
}

@-webkit-keyframes snow-47 {
  from {
    transform: translate(422px, -66px);
  }
  to {
    transform: translate(422px, 465px);
  }
}

@keyframes snow-47 {
  from {
    transform: translate(422px, -66px);
  }
  to {
    transform: translate(422px, 465px);
  }
}
.snowflake:nth-child(48) {
  -webkit-animation: snow-48 6s infinite;
          animation: snow-48 6s infinite;
}

@-webkit-keyframes snow-48 {
  from {
    transform: translate(189px, -136px);
  }
  to {
    transform: translate(189px, 641px);
  }
}

@keyframes snow-48 {
  from {
    transform: translate(189px, -136px);
  }
  to {
    transform: translate(189px, 641px);
  }
}
.snowflake:nth-child(49) {
  -webkit-animation: snow-49 11s infinite;
          animation: snow-49 11s infinite;
}

@-webkit-keyframes snow-49 {
  from {
    transform: translate(260px, -249px);
  }
  to {
    transform: translate(260px, 589px);
  }
}

@keyframes snow-49 {
  from {
    transform: translate(260px, -249px);
  }
  to {
    transform: translate(260px, 589px);
  }
}
.snowflake:nth-child(50) {
  -webkit-animation: snow-50 11s infinite;
          animation: snow-50 11s infinite;
}

@-webkit-keyframes snow-50 {
  from {
    transform: translate(141px, -172px);
  }
  to {
    transform: translate(141px, 461px);
  }
}

@keyframes snow-50 {
  from {
    transform: translate(141px, -172px);
  }
  to {
    transform: translate(141px, 461px);
  }
}
.snowflake:nth-child(51) {
  -webkit-animation: snow-51 13s infinite;
          animation: snow-51 13s infinite;
}

@-webkit-keyframes snow-51 {
  from {
    transform: translate(220px, -203px);
  }
  to {
    transform: translate(220px, 590px);
  }
}

@keyframes snow-51 {
  from {
    transform: translate(220px, -203px);
  }
  to {
    transform: translate(220px, 590px);
  }
}
.snowflake:nth-child(52) {
  -webkit-animation: snow-52 11s infinite;
          animation: snow-52 11s infinite;
}

@-webkit-keyframes snow-52 {
  from {
    transform: translate(13px, -178px);
  }
  to {
    transform: translate(13px, 542px);
  }
}

@keyframes snow-52 {
  from {
    transform: translate(13px, -178px);
  }
  to {
    transform: translate(13px, 542px);
  }
}
.snowflake:nth-child(53) {
  -webkit-animation: snow-53 9s infinite;
          animation: snow-53 9s infinite;
}

@-webkit-keyframes snow-53 {
  from {
    transform: translate(213px, -120px);
  }
  to {
    transform: translate(213px, 410px);
  }
}

@keyframes snow-53 {
  from {
    transform: translate(213px, -120px);
  }
  to {
    transform: translate(213px, 410px);
  }
}
.snowflake:nth-child(54) {
  -webkit-animation: snow-54 8s infinite;
          animation: snow-54 8s infinite;
}

@-webkit-keyframes snow-54 {
  from {
    transform: translate(303px, -133px);
  }
  to {
    transform: translate(303px, 664px);
  }
}

@keyframes snow-54 {
  from {
    transform: translate(303px, -133px);
  }
  to {
    transform: translate(303px, 664px);
  }
}
.snowflake:nth-child(55) {
  -webkit-animation: snow-55 13s infinite;
          animation: snow-55 13s infinite;
}

@-webkit-keyframes snow-55 {
  from {
    transform: translate(118px, -151px);
  }
  to {
    transform: translate(118px, 480px);
  }
}

@keyframes snow-55 {
  from {
    transform: translate(118px, -151px);
  }
  to {
    transform: translate(118px, 480px);
  }
}
.snowflake:nth-child(56) {
  -webkit-animation: snow-56 6s infinite;
          animation: snow-56 6s infinite;
}

@-webkit-keyframes snow-56 {
  from {
    transform: translate(234px, -61px);
  }
  to {
    transform: translate(234px, 402px);
  }
}

@keyframes snow-56 {
  from {
    transform: translate(234px, -61px);
  }
  to {
    transform: translate(234px, 402px);
  }
}
.snowflake:nth-child(57) {
  -webkit-animation: snow-57 12s infinite;
          animation: snow-57 12s infinite;
}

@-webkit-keyframes snow-57 {
  from {
    transform: translate(144px, -54px);
  }
  to {
    transform: translate(144px, 444px);
  }
}

@keyframes snow-57 {
  from {
    transform: translate(144px, -54px);
  }
  to {
    transform: translate(144px, 444px);
  }
}
.snowflake:nth-child(58) {
  -webkit-animation: snow-58 15s infinite;
          animation: snow-58 15s infinite;
}

@-webkit-keyframes snow-58 {
  from {
    transform: translate(260px, -138px);
  }
  to {
    transform: translate(260px, 667px);
  }
}

@keyframes snow-58 {
  from {
    transform: translate(260px, -138px);
  }
  to {
    transform: translate(260px, 667px);
  }
}
.snowflake:nth-child(59) {
  -webkit-animation: snow-59 7s infinite;
          animation: snow-59 7s infinite;
}

@-webkit-keyframes snow-59 {
  from {
    transform: translate(345px, -84px);
  }
  to {
    transform: translate(345px, 587px);
  }
}

@keyframes snow-59 {
  from {
    transform: translate(345px, -84px);
  }
  to {
    transform: translate(345px, 587px);
  }
}
.snowflake:nth-child(60) {
  -webkit-animation: snow-60 15s infinite;
          animation: snow-60 15s infinite;
}

@-webkit-keyframes snow-60 {
  from {
    transform: translate(394px, -195px);
  }
  to {
    transform: translate(394px, 479px);
  }
}

@keyframes snow-60 {
  from {
    transform: translate(394px, -195px);
  }
  to {
    transform: translate(394px, 479px);
  }
}
.snowflake:nth-child(61) {
  -webkit-animation: snow-61 10s infinite;
          animation: snow-61 10s infinite;
}

@-webkit-keyframes snow-61 {
  from {
    transform: translate(345px, -24px);
  }
  to {
    transform: translate(345px, 645px);
  }
}

@keyframes snow-61 {
  from {
    transform: translate(345px, -24px);
  }
  to {
    transform: translate(345px, 645px);
  }
}
.snowflake:nth-child(62) {
  -webkit-animation: snow-62 13s infinite;
          animation: snow-62 13s infinite;
}

@-webkit-keyframes snow-62 {
  from {
    transform: translate(195px, -71px);
  }
  to {
    transform: translate(195px, 504px);
  }
}

@keyframes snow-62 {
  from {
    transform: translate(195px, -71px);
  }
  to {
    transform: translate(195px, 504px);
  }
}
.snowflake:nth-child(63) {
  -webkit-animation: snow-63 8s infinite;
          animation: snow-63 8s infinite;
}

@-webkit-keyframes snow-63 {
  from {
    transform: translate(213px, -3px);
  }
  to {
    transform: translate(213px, 647px);
  }
}

@keyframes snow-63 {
  from {
    transform: translate(213px, -3px);
  }
  to {
    transform: translate(213px, 647px);
  }
}
.snowflake:nth-child(64) {
  -webkit-animation: snow-64 8s infinite;
          animation: snow-64 8s infinite;
}

@-webkit-keyframes snow-64 {
  from {
    transform: translate(226px, -23px);
  }
  to {
    transform: translate(226px, 610px);
  }
}

@keyframes snow-64 {
  from {
    transform: translate(226px, -23px);
  }
  to {
    transform: translate(226px, 610px);
  }
}
.snowflake:nth-child(65) {
  -webkit-animation: snow-65 11s infinite;
          animation: snow-65 11s infinite;
}

@-webkit-keyframes snow-65 {
  from {
    transform: translate(347px, -220px);
  }
  to {
    transform: translate(347px, 587px);
  }
}

@keyframes snow-65 {
  from {
    transform: translate(347px, -220px);
  }
  to {
    transform: translate(347px, 587px);
  }
}
.snowflake:nth-child(66) {
  -webkit-animation: snow-66 7s infinite;
          animation: snow-66 7s infinite;
}

@-webkit-keyframes snow-66 {
  from {
    transform: translate(284px, -190px);
  }
  to {
    transform: translate(284px, 511px);
  }
}

@keyframes snow-66 {
  from {
    transform: translate(284px, -190px);
  }
  to {
    transform: translate(284px, 511px);
  }
}
.snowflake:nth-child(67) {
  -webkit-animation: snow-67 8s infinite;
          animation: snow-67 8s infinite;
}

@-webkit-keyframes snow-67 {
  from {
    transform: translate(283px, -274px);
  }
  to {
    transform: translate(283px, 471px);
  }
}

@keyframes snow-67 {
  from {
    transform: translate(283px, -274px);
  }
  to {
    transform: translate(283px, 471px);
  }
}
.snowflake:nth-child(68) {
  -webkit-animation: snow-68 11s infinite;
          animation: snow-68 11s infinite;
}

@-webkit-keyframes snow-68 {
  from {
    transform: translate(182px, -269px);
  }
  to {
    transform: translate(182px, 537px);
  }
}

@keyframes snow-68 {
  from {
    transform: translate(182px, -269px);
  }
  to {
    transform: translate(182px, 537px);
  }
}
.snowflake:nth-child(69) {
  -webkit-animation: snow-69 6s infinite;
          animation: snow-69 6s infinite;
}

@-webkit-keyframes snow-69 {
  from {
    transform: translate(36px, -106px);
  }
  to {
    transform: translate(36px, 497px);
  }
}

@keyframes snow-69 {
  from {
    transform: translate(36px, -106px);
  }
  to {
    transform: translate(36px, 497px);
  }
}
.snowflake:nth-child(70) {
  -webkit-animation: snow-70 15s infinite;
          animation: snow-70 15s infinite;
}

@-webkit-keyframes snow-70 {
  from {
    transform: translate(278px, -205px);
  }
  to {
    transform: translate(278px, 671px);
  }
}

@keyframes snow-70 {
  from {
    transform: translate(278px, -205px);
  }
  to {
    transform: translate(278px, 671px);
  }
}
.snowflake:nth-child(71) {
  -webkit-animation: snow-71 9s infinite;
          animation: snow-71 9s infinite;
}

@-webkit-keyframes snow-71 {
  from {
    transform: translate(143px, -153px);
  }
  to {
    transform: translate(143px, 577px);
  }
}

@keyframes snow-71 {
  from {
    transform: translate(143px, -153px);
  }
  to {
    transform: translate(143px, 577px);
  }
}
.snowflake:nth-child(72) {
  -webkit-animation: snow-72 14s infinite;
          animation: snow-72 14s infinite;
}

@-webkit-keyframes snow-72 {
  from {
    transform: translate(55px, -149px);
  }
  to {
    transform: translate(55px, 623px);
  }
}

@keyframes snow-72 {
  from {
    transform: translate(55px, -149px);
  }
  to {
    transform: translate(55px, 623px);
  }
}
.snowflake:nth-child(73) {
  -webkit-animation: snow-73 6s infinite;
          animation: snow-73 6s infinite;
}

@-webkit-keyframes snow-73 {
  from {
    transform: translate(213px, -114px);
  }
  to {
    transform: translate(213px, 658px);
  }
}

@keyframes snow-73 {
  from {
    transform: translate(213px, -114px);
  }
  to {
    transform: translate(213px, 658px);
  }
}
.snowflake:nth-child(74) {
  -webkit-animation: snow-74 8s infinite;
          animation: snow-74 8s infinite;
}

@-webkit-keyframes snow-74 {
  from {
    transform: translate(71px, -48px);
  }
  to {
    transform: translate(71px, 577px);
  }
}

@keyframes snow-74 {
  from {
    transform: translate(71px, -48px);
  }
  to {
    transform: translate(71px, 577px);
  }
}
.snowflake:nth-child(75) {
  -webkit-animation: snow-75 13s infinite;
          animation: snow-75 13s infinite;
}

@-webkit-keyframes snow-75 {
  from {
    transform: translate(216px, -26px);
  }
  to {
    transform: translate(216px, 554px);
  }
}

@keyframes snow-75 {
  from {
    transform: translate(216px, -26px);
  }
  to {
    transform: translate(216px, 554px);
  }
}
.snowflake:nth-child(76) {
  -webkit-animation: snow-76 13s infinite;
          animation: snow-76 13s infinite;
}

@-webkit-keyframes snow-76 {
  from {
    transform: translate(373px, -297px);
  }
  to {
    transform: translate(373px, 584px);
  }
}

@keyframes snow-76 {
  from {
    transform: translate(373px, -297px);
  }
  to {
    transform: translate(373px, 584px);
  }
}
.snowflake:nth-child(77) {
  -webkit-animation: snow-77 15s infinite;
          animation: snow-77 15s infinite;
}

@-webkit-keyframes snow-77 {
  from {
    transform: translate(288px, -151px);
  }
  to {
    transform: translate(288px, 533px);
  }
}

@keyframes snow-77 {
  from {
    transform: translate(288px, -151px);
  }
  to {
    transform: translate(288px, 533px);
  }
}
.snowflake:nth-child(78) {
  -webkit-animation: snow-78 6s infinite;
          animation: snow-78 6s infinite;
}

@-webkit-keyframes snow-78 {
  from {
    transform: translate(27px, -194px);
  }
  to {
    transform: translate(27px, 694px);
  }
}

@keyframes snow-78 {
  from {
    transform: translate(27px, -194px);
  }
  to {
    transform: translate(27px, 694px);
  }
}
.snowflake:nth-child(79) {
  -webkit-animation: snow-79 7s infinite;
          animation: snow-79 7s infinite;
}

@-webkit-keyframes snow-79 {
  from {
    transform: translate(324px, -22px);
  }
  to {
    transform: translate(324px, 636px);
  }
}

@keyframes snow-79 {
  from {
    transform: translate(324px, -22px);
  }
  to {
    transform: translate(324px, 636px);
  }
}
.snowflake:nth-child(80) {
  -webkit-animation: snow-80 13s infinite;
          animation: snow-80 13s infinite;
}

@-webkit-keyframes snow-80 {
  from {
    transform: translate(260px, -134px);
  }
  to {
    transform: translate(260px, 660px);
  }
}

@keyframes snow-80 {
  from {
    transform: translate(260px, -134px);
  }
  to {
    transform: translate(260px, 660px);
  }
}
.snowflake:nth-child(81) {
  -webkit-animation: snow-81 15s infinite;
          animation: snow-81 15s infinite;
}

@-webkit-keyframes snow-81 {
  from {
    transform: translate(22px, -54px);
  }
  to {
    transform: translate(22px, 689px);
  }
}

@keyframes snow-81 {
  from {
    transform: translate(22px, -54px);
  }
  to {
    transform: translate(22px, 689px);
  }
}
.snowflake:nth-child(82) {
  -webkit-animation: snow-82 6s infinite;
          animation: snow-82 6s infinite;
}

@-webkit-keyframes snow-82 {
  from {
    transform: translate(235px, -24px);
  }
  to {
    transform: translate(235px, 689px);
  }
}

@keyframes snow-82 {
  from {
    transform: translate(235px, -24px);
  }
  to {
    transform: translate(235px, 689px);
  }
}
.snowflake:nth-child(83) {
  -webkit-animation: snow-83 13s infinite;
          animation: snow-83 13s infinite;
}

@-webkit-keyframes snow-83 {
  from {
    transform: translate(180px, -269px);
  }
  to {
    transform: translate(180px, 455px);
  }
}

@keyframes snow-83 {
  from {
    transform: translate(180px, -269px);
  }
  to {
    transform: translate(180px, 455px);
  }
}
.snowflake:nth-child(84) {
  -webkit-animation: snow-84 15s infinite;
          animation: snow-84 15s infinite;
}

@-webkit-keyframes snow-84 {
  from {
    transform: translate(318px, -289px);
  }
  to {
    transform: translate(318px, 490px);
  }
}

@keyframes snow-84 {
  from {
    transform: translate(318px, -289px);
  }
  to {
    transform: translate(318px, 490px);
  }
}
.snowflake:nth-child(85) {
  -webkit-animation: snow-85 14s infinite;
          animation: snow-85 14s infinite;
}

@-webkit-keyframes snow-85 {
  from {
    transform: translate(204px, -44px);
  }
  to {
    transform: translate(204px, 553px);
  }
}

@keyframes snow-85 {
  from {
    transform: translate(204px, -44px);
  }
  to {
    transform: translate(204px, 553px);
  }
}
.snowflake:nth-child(86) {
  -webkit-animation: snow-86 9s infinite;
          animation: snow-86 9s infinite;
}

@-webkit-keyframes snow-86 {
  from {
    transform: translate(408px, -63px);
  }
  to {
    transform: translate(408px, 415px);
  }
}

@keyframes snow-86 {
  from {
    transform: translate(408px, -63px);
  }
  to {
    transform: translate(408px, 415px);
  }
}
.snowflake:nth-child(87) {
  -webkit-animation: snow-87 10s infinite;
          animation: snow-87 10s infinite;
}

@-webkit-keyframes snow-87 {
  from {
    transform: translate(444px, -55px);
  }
  to {
    transform: translate(444px, 619px);
  }
}

@keyframes snow-87 {
  from {
    transform: translate(444px, -55px);
  }
  to {
    transform: translate(444px, 619px);
  }
}
.snowflake:nth-child(88) {
  -webkit-animation: snow-88 7s infinite;
          animation: snow-88 7s infinite;
}

@-webkit-keyframes snow-88 {
  from {
    transform: translate(342px, -56px);
  }
  to {
    transform: translate(342px, 629px);
  }
}

@keyframes snow-88 {
  from {
    transform: translate(342px, -56px);
  }
  to {
    transform: translate(342px, 629px);
  }
}
.snowflake:nth-child(89) {
  -webkit-animation: snow-89 14s infinite;
          animation: snow-89 14s infinite;
}

@-webkit-keyframes snow-89 {
  from {
    transform: translate(309px, -218px);
  }
  to {
    transform: translate(309px, 630px);
  }
}

@keyframes snow-89 {
  from {
    transform: translate(309px, -218px);
  }
  to {
    transform: translate(309px, 630px);
  }
}
.snowflake:nth-child(90) {
  -webkit-animation: snow-90 12s infinite;
          animation: snow-90 12s infinite;
}

@-webkit-keyframes snow-90 {
  from {
    transform: translate(63px, -296px);
  }
  to {
    transform: translate(63px, 496px);
  }
}

@keyframes snow-90 {
  from {
    transform: translate(63px, -296px);
  }
  to {
    transform: translate(63px, 496px);
  }
}
.snowflake:nth-child(91) {
  -webkit-animation: snow-91 9s infinite;
          animation: snow-91 9s infinite;
}

@-webkit-keyframes snow-91 {
  from {
    transform: translate(247px, -194px);
  }
  to {
    transform: translate(247px, 628px);
  }
}

@keyframes snow-91 {
  from {
    transform: translate(247px, -194px);
  }
  to {
    transform: translate(247px, 628px);
  }
}
.snowflake:nth-child(92) {
  -webkit-animation: snow-92 8s infinite;
          animation: snow-92 8s infinite;
}

@-webkit-keyframes snow-92 {
  from {
    transform: translate(230px, -188px);
  }
  to {
    transform: translate(230px, 565px);
  }
}

@keyframes snow-92 {
  from {
    transform: translate(230px, -188px);
  }
  to {
    transform: translate(230px, 565px);
  }
}
.snowflake:nth-child(93) {
  -webkit-animation: snow-93 9s infinite;
          animation: snow-93 9s infinite;
}

@-webkit-keyframes snow-93 {
  from {
    transform: translate(6px, -177px);
  }
  to {
    transform: translate(6px, 641px);
  }
}

@keyframes snow-93 {
  from {
    transform: translate(6px, -177px);
  }
  to {
    transform: translate(6px, 641px);
  }
}
.snowflake:nth-child(94) {
  -webkit-animation: snow-94 10s infinite;
          animation: snow-94 10s infinite;
}

@-webkit-keyframes snow-94 {
  from {
    transform: translate(279px, -124px);
  }
  to {
    transform: translate(279px, 434px);
  }
}

@keyframes snow-94 {
  from {
    transform: translate(279px, -124px);
  }
  to {
    transform: translate(279px, 434px);
  }
}
.snowflake:nth-child(95) {
  -webkit-animation: snow-95 10s infinite;
          animation: snow-95 10s infinite;
}

@-webkit-keyframes snow-95 {
  from {
    transform: translate(287px, -107px);
  }
  to {
    transform: translate(287px, 581px);
  }
}

@keyframes snow-95 {
  from {
    transform: translate(287px, -107px);
  }
  to {
    transform: translate(287px, 581px);
  }
}
.snowflake:nth-child(96) {
  -webkit-animation: snow-96 11s infinite;
          animation: snow-96 11s infinite;
}

@-webkit-keyframes snow-96 {
  from {
    transform: translate(58px, -218px);
  }
  to {
    transform: translate(58px, 598px);
  }
}

@keyframes snow-96 {
  from {
    transform: translate(58px, -218px);
  }
  to {
    transform: translate(58px, 598px);
  }
}
.snowflake:nth-child(97) {
  -webkit-animation: snow-97 8s infinite;
          animation: snow-97 8s infinite;
}

@-webkit-keyframes snow-97 {
  from {
    transform: translate(62px, -279px);
  }
  to {
    transform: translate(62px, 414px);
  }
}

@keyframes snow-97 {
  from {
    transform: translate(62px, -279px);
  }
  to {
    transform: translate(62px, 414px);
  }
}
.snowflake:nth-child(98) {
  -webkit-animation: snow-98 12s infinite;
          animation: snow-98 12s infinite;
}

@-webkit-keyframes snow-98 {
  from {
    transform: translate(278px, -87px);
  }
  to {
    transform: translate(278px, 485px);
  }
}

@keyframes snow-98 {
  from {
    transform: translate(278px, -87px);
  }
  to {
    transform: translate(278px, 485px);
  }
}
.snowflake:nth-child(99) {
  -webkit-animation: snow-99 15s infinite;
          animation: snow-99 15s infinite;
}

@-webkit-keyframes snow-99 {
  from {
    transform: translate(148px, -240px);
  }
  to {
    transform: translate(148px, 607px);
  }
}

@keyframes snow-99 {
  from {
    transform: translate(148px, -240px);
  }
  to {
    transform: translate(148px, 607px);
  }
}
.snowflake:nth-child(100) {
  -webkit-animation: snow-100 11s infinite;
          animation: snow-100 11s infinite;
}

@-webkit-keyframes snow-100 {
  from {
    transform: translate(302px, -183px);
  }
  to {
    transform: translate(302px, 536px);
  }
}

@keyframes snow-100 {
  from {
    transform: translate(302px, -183px);
  }
  to {
    transform: translate(302px, 536px);
  }
}
@-webkit-keyframes tail {
  10% {
    transform: rotate(2deg);
  }
  20% {
    transform: rotate(-5deg);
  }
}
@keyframes tail {
  10% {
    transform: rotate(2deg);
  }
  20% {
    transform: rotate(-5deg);
  }
}
@-webkit-keyframes shadow {
  to {
    width: 185px;
  }
}
@keyframes shadow {
  to {
    width: 185px;
  }
}
@-webkit-keyframes eyes {
  50% {
    transform: translate(3px, 2px);
  }
  60% {
    transform: translate(0, 0);
  }
  100% {
    transform: translate(0, 0);
  }
}
@keyframes eyes {
  50% {
    transform: translate(3px, 2px);
  }
  60% {
    transform: translate(0, 0);
  }
  100% {
    transform: translate(0, 0);
  }
}
@-webkit-keyframes eaves {
  50% {
    transform: translateY(0);
  }
  60% {
    transform: translateY(-1px);
  }
  100% {
    transform: translateY(-1px);
  }
}
@keyframes eaves {
  50% {
    transform: translateY(0);
  }
  60% {
    transform: translateY(-1px);
  }
  100% {
    transform: translateY(-1px);
  }
}
@-webkit-keyframes hoof-one {
  to {
    transform: translateX(2px) rotate(5deg);
  }
}
@keyframes hoof-one {
  to {
    transform: translateX(2px) rotate(5deg);
  }
}
@-webkit-keyframes jump {
  to {
    transform: translateY(-2px) rotate(25deg);
  }
}
@keyframes jump {
  to {
    transform: translateY(-2px) rotate(25deg);
  }
}
@-webkit-keyframes jump-two {
  to {
    transform: translateY(2px);
  }
}
@keyframes jump-two {
  to {
    transform: translateY(2px);
  }
}
@-webkit-keyframes rocking {
  to {
    transform: rotate(-1deg);
  }
}
@keyframes rocking {
  to {
    transform: rotate(-1deg);
  }
}
@-webkit-keyframes ear-left {
  85% {
    transform: rotate(30deg);
  }
  100% {
    transform: rotate(-10deg);
  }
}
@keyframes ear-left {
  85% {
    transform: rotate(30deg);
  }
  100% {
    transform: rotate(-10deg);
  }
}
@-webkit-keyframes ear-right {
  85% {
    transform: rotate(160deg);
  }
  100% {
    transform: rotate(170deg);
  }
}
@keyframes ear-right {
  85% {
    transform: rotate(160deg);
  }
  100% {
    transform: rotate(170deg);
  }
}
@-webkit-keyframes leg-right {
  to {
    transform: translateX(4px) rotate(2deg);
  }
}
@keyframes leg-right {
  to {
    transform: translateX(4px) rotate(2deg);
  }
}
@-webkit-keyframes leg-left {
  0% {
    transform: rotate(0deg) translateX(0px);
  }
  50% {
    transform: rotate(5deg) translateX(3px);
  }
}
@keyframes leg-left {
  0% {
    transform: rotate(0deg) translateX(0px);
  }
  50% {
    transform: rotate(5deg) translateX(3px);
  }
}
a {
  font-weight: 600;
  color: #91a7ff;
  text-decoration: none;
}
a:hover {
  color: #5c7cfa;
  text-decoration: underline;
}

html,
body {
  font-family: "Open Sans";
}

body {
  background-color: #f8f9fa;
  color: #adb5bd;
}

.title {
  text-align: center;
}
.title h1 {
  font-size: 1.5em;
  margin: 100px 0 10px 0;
}

.socials {
  display: block;
  font-size: 14px;
  margin: 0;
  padding: 0;
}
.socials li {
  display: inline;
}
.socials li:not(:last-child) {
  margin-right: 0.75em;
}
.socials li a {
  vertical-align: middle;
}
.socials li a:hover img {
  -webkit-animation: link 0.5s;
          animation: link 0.5s;
}
.socials li a img {
  width: 1.3em;
}

.credits {
  font-size: 0.8em;
  text-align: center;
}

.love {
  background: url(https://s3-us-west-2.amazonaws.com/s.cdpn.io/42764/heart-smil.svg);
  display: inline-block;
  height: 16px;
  vertical-align: middle;
  width: 16px;
}

.container {
  background-color: white;
  border-radius: 4px;
  box-shadow: 0 1px 3px #dee2e6;
  height: 300px;
  margin: 40px auto 50px auto;
  position: relative;
  width: 450px;
}

.artboard {
  height: 100%;
  overflow: hidden;
  position: relative;
  width: 100%;
}

@-webkit-keyframes link {
  25% {
    transform: rotate(10deg);
  }
  50% {
    transform: rotate(-10deg);
  }
}

@keyframes link {
  25% {
    transform: rotate(10deg);
  }
  50% {
    transform: rotate(-10deg);
  }
}
    </style>
    <h1 id="error-message">You have not registerd for the game
  </div>
  <div class="container">
    <div class="artboard">
      <div class="deer">
        <div class="rocking">
          <div class="head">
            <div class="horns">
              <div class="horn horn-left">
                <div class="line line-one"></div>
                <div class="line"></div>
                <div class="line line-three"></div>
              </div>
              <div class="horn horn-right">
                <div class="line line-one"></div>
                <div class="line"></div>
                <div class="line line-three"></div>
              </div>
            </div>
            <div class="ears">
              <div class="ear ear-left"></div>
              <div class="ear ear-right"></div>
            </div>
            <div class="eyes">
              <div class="eye eye-left"></div>
              <div class="eye eye-right"></div>
            </div>
            <div class="nose"></div>
          </div>
          <div class="body">
            <div class="shadow"></div>
            <div class="hooves">
              <div class="hoof-one">
                <div class="line"></div>
                <div class="anim-part">
                  <div class="circle">
                    <div class="circle">
                      <div class="circle">
                        <div class="circle">
                          <div class="circle circle-last"></div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div class="hoof-two">
                <div class="line-one"></div>
                <div class="line-two"></div>
              </div>
            </div>
          </div>
          <div class="tail">
            <div class="circle">
              <div class="circle">
                <div class="circle">
                  <div class="circle">
                    <div class="circle"></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div class="legs">
          <div class="leg-left">
            <div class="anim-part">
              <div class="line"></div>
            </div>
          </div>
          <div class="leg-right">
            <div class="anim-part">
              <div class="circle">
                <div class="circle">
                  <div class="circle">
                    <div class="circle">
                      <div class="circle">
                        <div class="circle">
                          <div class="circle">
                            <div class="circle">
                              <div class="circle circle-last"></div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="presents">
        <div class="present present-one"></div>
        <div class="present present-two"></div>
        <div class="present present-two present-two-right"></div>
        <div class="present present-three"></div>
      </div>
      <div class="snow"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
      <div class="snowflake"></div>
    </div>
  </div>
  </body>
</html>
    `
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(html))
}


func submitNamesHandler(w http.ResponseWriter, r *http.Request) {
	var req NamesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	// Open the file for appending or create it if it doesn't exist
	file, err := os.OpenFile("guessed_names.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, "Unable to open CSV file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Check if the file is empty to write headers (optional)
	_, err = file.Stat()
	if err != nil {
		http.Error(w, "Unable to read CSV file info", http.StatusInternalServerError)
		return
	}

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Extract username from the first formatted name (assuming it's consistent)
	if len(req.Names) > 0 {
		// Split the username and the first name from the formatted string
		parts := strings.SplitN(req.Names[0], " -> ", 2)
		if len(parts) != 2 {
			http.Error(w, "Invalid name format", http.StatusBadRequest)
			return
		}

		username := parts[0]
		// Extract only the names (strip the username part)
		var names []string
		for _, name := range req.Names {
			parts := strings.SplitN(name, " -> ", 2)
			if len(parts) == 2 {
				// Remove quotes around the name
				names = append(names, strings.Trim(parts[1], "'"))
			}
		}

		// Write the row with the username followed by names
		record := append([]string{username}, names...)
		if err := writer.Write(record); err != nil {
			http.Error(w, "Unable to write to CSV file", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Guesses names submitted successfully!"})
}