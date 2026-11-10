import { createRouter, createWebHistory } from "vue-router";

import CheckView from "./views/CheckView.vue";
import ResultView from "./views/ResultView.vue";

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", name: "check", component: CheckView },
    { path: "/check/:host", name: "result", component: ResultView },
  ],
});
