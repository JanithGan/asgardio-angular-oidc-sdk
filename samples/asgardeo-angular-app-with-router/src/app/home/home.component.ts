/**
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

import { Component, OnInit } from "@angular/core";
import { AsgardeoAuthService } from "@asgardeo/auth-angular";

@Component({
    selector: "app-home",
    templateUrl: "./home.component.html",
    styleUrls: ["./home.component.css"]
})
export class HomeComponent implements OnInit {
    isAuthenticated: boolean;

    constructor(private auth: AsgardeoAuthService) { }

    ngOnInit() {
        this.auth.isAuthenticated().subscribe((payload) => this.isAuthenticated = payload);
    }

    handleLogin(): void {
        this.auth.signInWithRedirect();
    }

    handleLogout(): void {
        this.auth.signOut();
    }
}
